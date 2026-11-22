//! OpenVPN 出口连接器实现（RIL-122）。
//!
//! 三层 VPN 客户端面（库承载——`corevpn-protocol` 0.6.0，MIT OR Apache-2.0；
//! 评估与标准对端互通留证 protocol-backends.md#openvpn：真机对端 = apt
//! openvpn 2.7.0，TLS 1.3 + KeyMethodV2 + PUSH_REPLY + 数据通道密钥派生
//! 实测通过）。本模块嵌入载具 `ProtocolSession` + `TlsClientHandler`：
//! 控制通道 = HARD_RESET_CLIENT_V2 → 可靠传输上的 TLS 握手 → KeyMethodV2
//! 交换（openvpn_prf 派生数据通道密钥）→ PUSH_REPLY（ifconfig/routes/
//! dns/gateway）；数据面 = UDP 数据通道加密 IP 包（AES-256-GCM /
//! CHACHA20-POLY1305），三层桥（用户态 smoltcp，与 OpenConnect 连接器
//! 共用 [`super::openconnect::EgressStack`])。
//!
//! 线格式与驱动流程对照 corevpn-cli client.rs 核读（载具仓 0.6.0）：
//! - HARD_RESET_CLIENT_V2（opcode P_CLIENT_V2 + 本端会话 id）→ 服务端
//!   HARD_RESET_SERVER_V2（携服务端会话 id）→ ACK；
//! - TLS 记录骑可靠传输（packet-id 重传/去重 + TlsRecordReassembler），
//!   握手完成后 KeyMethodV2 明文与 TLS Finished 同批冲刷（服务端单轮
//!   处理语义）；
//! - KeyMethodV2 客户端格式：0x00 + 0x02 + pre_master(48) + random1(32)
//!   + random2(32) + length-prefixed options/username/password/peer_info；
//!     服务端格式无 pre_master（`parse_from_server`）；
//! - PRF 派生：master_secret = PRF(pre_master, "OpenVPN master secret",
//!   client_r1‖server_r1, 48)；key_block = PRF(master_secret, "OpenVPN key
//!   expansion", client_r2‖server_r2‖client_sid‖server_sid, 256)；
//!   `KeyMaterial::from_openvpn_key2_block` 切钥，客户端安装向（encrypt
//!   用 client钥、decrypt 用 server钥）；
//! - 数据通道包 = OpenVPN 数据头（opcode P_DATA_V2 + peer-id）+ AEAD 密文
//!   （载具 PacketCipher 封装）；PING = 16 字节魔术载荷（0x2a 0x18 0x7b
//!   0xf3 …），收到即原样回（非 IP 包，不入栈）。
//!
//! 安全姿态（具名边界，见 protocol-backends.md#openvpn）：载具
//! CoreVpnServerVerifier 放宽服务端证书链核验（非空根库即放行——不校
//! 链/EKU/SAN；TLS 握手内签名方案仍经 rustls 校验），故本面无
//! skip_cert_verify 开关（IR 不留字段）；ca_pem 必填且非空（载具硬要求）。
//! UDP/QUIC 应用面不交付（catalog udp=false，三层桥仅 TCP socket 面）；
//! 服务端面不交付；系统 TUN 路线未走（用户态栈）。

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;
use tokio::net::UdpSocket;

use corevpn_crypto::{openvpn_prf, random_bytes, CipherSuite, HmacAuth, KeyMaterial};
use corevpn_protocol::{
    create_client_config, load_certs_from_pem, load_key_from_pem, KeyMethodV2, ProcessedPacket,
    ProtocolSession, ProtocolState, PushReply, TlsClientHandler,
};

use super::openconnect::{netmask_to_prefix, EgressStack, EgressTcpStream, TunnelInfo};

/// 会话建立（握手 + 密钥派生 + PUSH_REPLY）超时上限
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// 单次收包缓冲（控制面 UDP 报文上限）
const RECV_BUF: usize = 65536;
/// OpenVPN PING 魔术载荷（16 字节；收到即原样回，不入栈）
const PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7,
    0x48,
];
/// 载具 peer_info（IV_* 集合；NCP 协商面）。
///
/// `IV_PROTO=20` 只广告数据面真实实现的位：`request-push`(0x04) 与 `dns-option`(0x10)。
/// 刻意**不**广告 `data-v2`(0x02) 与 `tls-ekm`(0x08)——载具数据面只做经典 PRF 派生 +
/// P_DATA_V1，广告它们会让服务端协商出 `key-derivation tls-ekm` + `peer-id`，
/// 于是密钥与帧格式都不匹配，隧道建成但数据面必死。
const PEER_INFO: &str = "IV_VER=corevpn-0.4.0\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=20\nIV_CIPHERS=CHACHA20-POLY1305:AES-256-GCM:AES-128-GCM\n";
/// 握手循环防御上界（与载具 CLI 同值）
const MAX_HANDSHAKE_ATTEMPTS: usize = 50;
const MAX_KM_ATTEMPTS: usize = 100;

/// OpenVPN 连接配置（IR `EgressConfig::OpenVpn` 展开）。
#[derive(Debug, Clone)]
pub(crate) struct OpenVpnConfig {
    pub(crate) server: String,
    pub(crate) port: u16,
    /// CA 证书 PEM（必填非空——载具根库非空硬要求）
    pub(crate) ca_pem: String,
    /// 客户端证书 PEM（必填——标准 openvpn 证书认证）
    pub(crate) cert_pem: String,
    /// 客户端私钥 PEM（必填）
    pub(crate) key_pem: String,
    /// 数据通道密码（AES-256-GCM | CHACHA20-POLY1305）
    pub(crate) cipher: String,
    /// tls-auth 静态密钥（ta.key 解出的 256 原始字节；可空）
    pub(crate) tls_auth_key: Option<Vec<u8>>,
    /// tls-auth key-direction（0/1；可空）
    pub(crate) key_direction: Option<u8>,
    /// SNI（缺省回落 server；载具核验器忽略 server_name，仅作 ClientHello SNI）
    pub(crate) sni: Option<String>,
}

/// 数据通道密码解析（白名单外具名拒绝）。
fn cipher_suite_of(cipher: &str) -> Result<CipherSuite> {
    match cipher.to_uppercase().as_str() {
        "CHACHA20-POLY1305" => Ok(CipherSuite::ChaCha20Poly1305),
        "AES-256-GCM" => Ok(CipherSuite::Aes256Gcm),
        other => Err(anyhow!("openvpn 数据通道密码不支持：{other}（白名单 AES-256-GCM / CHACHA20-POLY1305）")),
    }
}

/// 从服务端 KeyMethodV2 options 串取 tun-mtu（缺省 1500）。
fn tun_mtu_of(options: &str) -> u16 {
    for part in options.split(',') {
        if let Some(v) = part.trim().strip_prefix("tun-mtu ") {
            if let Ok(n) = v.trim().parse::<u16>() {
                if (576..=65535).contains(&n) {
                    return n;
                }
            }
        }
    }
    1500
}

/// PUSH_REPLY → 三层桥栈参数（与 OpenConnect TunnelInfo 同构）。
///
/// DNS 服务器逐个按 IPv4 字面量解析（字面量外跳过——隧道 DNS 自举面无
/// 域名解析途径）；掩码点分十进制 → 前缀（`netmask_to_prefix` 同口径）。
fn tunnel_info_from(push: &PushReply, mtu: u16) -> Result<TunnelInfo> {
    let (ip, mask) = push
        .ifconfig
        .as_ref()
        .context("PUSH_REPLY 缺 ifconfig（无法定位隧道地址）")?;
    let address: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("PUSH_REPLY ifconfig 地址非法：{ip}"))?;
    let mask_v4: Ipv4Addr = mask
        .parse()
        .with_context(|| format!("PUSH_REPLY ifconfig 掩码非法：{mask}"))?;
    let dns = push
        .dns
        .iter()
        .filter_map(|d| d.trim().parse::<Ipv4Addr>().ok())
        .collect();
    Ok(TunnelInfo {
        address,
        prefix: netmask_to_prefix(mask_v4),
        dns,
        mtu,
    })
}

/// 收包直到谓词命中（硬复位面；不回 ACK——ACK 由调用方按载具 CLI 语义补发）。
async fn recv_until(
    socket: &mut UdpSocket,
    session: &mut ProtocolSession,
    buf: &mut [u8],
    condition: impl Fn(&ProcessedPacket) -> bool,
) -> Result<ProcessedPacket> {
    loop {
        let n = socket.recv(buf).await.context("收包失败")?;
        let result = session
            .process_packet(&buf[..n])
            .map_err(|e| anyhow!("报文处理失败：{e}"))?;
        if condition(&result) {
            return Ok(result);
        }
    }
}

/// 补发 ACK 与重传（载具 CLI 语义：任何收包/冲刷后都查）。
async fn send_acks_and_retransmits(socket: &mut UdpSocket, session: &mut ProtocolSession) {
    if session.should_send_ack() {
        if let Some(ack) = session.create_ack_packet() {
            let _ = socket.send(&ack).await;
        }
    }
    for pkt in session.get_retransmits() {
        let _ = socket.send(&pkt).await;
    }
}

/// 把 TLS 待发数据收拢成一批控制包发出（载具 flush_tls_to_socket 口径：
/// Finished 与紧随的 KeyMethodV2 必须同批到达——服务端单轮处理）。
async fn flush_tls(
    socket: &mut UdpSocket,
    session: &mut ProtocolSession,
    tls: &mut TlsClientHandler,
) -> Result<()> {
    let mut all = Vec::new();
    while tls.wants_write() {
        match tls.get_outgoing().map_err(|e| anyhow!("TLS 出包失败：{e}"))? {
            Some(out) => all.extend_from_slice(&out),
            None => break,
        }
    }
    if all.is_empty() {
        return Ok(());
    }
    let ctrl = session
        .create_control_packets(Bytes::from(all))
        .map_err(|e| anyhow!("控制包构造失败：{e}"))?;
    for pkt in &ctrl {
        socket.send(pkt).await?;
    }
    Ok(())
}

/// 计算服务端 KeyMethodV2 字节长度（无 pre_master；定长头 69 + 三个
/// length-prefixed 串 options/username/password——载具 CLI 同口径）。
fn calculate_km_size(data: &[u8]) -> Result<usize> {
    if data.len() < 71 {
        bail!("KeyMethodV2 数据过短");
    }
    let mut offset = 69;
    for _ in 0..3 {
        if offset + 2 > data.len() {
            break;
        }
        let str_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        if offset + 2 + str_len > data.len() {
            break;
        }
        offset += 2 + str_len;
    }
    Ok(offset)
}

/// 从累积明文解析服务端 KeyMethodV2 与 PUSH_REPLY（载具
/// try_parse_server_messages 口径：KM 定长取出，剩余明文剥离分隔 0 字节
/// 后按控制消息前缀分派）。
fn try_parse_server_messages(
    total_plaintext: &mut Vec<u8>,
    server_km: &mut Option<KeyMethodV2>,
    push_reply: &mut Option<PushReply>,
) -> Result<()> {
    if server_km.is_none() && total_plaintext.len() >= 71 {
        if let Ok(km) = KeyMethodV2::parse_from_server(total_plaintext) {
            let km_size = calculate_km_size(total_plaintext)?;
            let remaining = total_plaintext.split_off(km_size);
            *total_plaintext = remaining;
            *server_km = Some(km);
        }
    }
    if server_km.is_some() && !total_plaintext.is_empty() {
        while total_plaintext.first() == Some(&0) {
            total_plaintext.remove(0);
        }
        if total_plaintext.is_empty() {
            return Ok(());
        }
        let msg = String::from_utf8_lossy(total_plaintext);
        let msg_str = msg.trim_end_matches('\0');
        if msg_str.starts_with("PUSH_REPLY") {
            *push_reply = Some(
                PushReply::parse(msg_str).map_err(|e| anyhow!("PUSH_REPLY 解析失败：{e}"))?,
            );
        }
    }
    Ok(())
}

/// 构造载具 TLS 客户端（CA + 客户端证书 mTLS；server_name 仅作 SNI——
/// 载具核验器忽略之，见模块头安全姿态）。
fn setup_tls_client(cfg: &OpenVpnConfig) -> Result<TlsClientHandler> {
    let ca = load_certs_from_pem(&cfg.ca_pem)
        .map_err(|e| anyhow!("CA 证书解析失败：{e}"))?
        .into_iter()
        .collect::<Vec<_>>();
    let client_certs = load_certs_from_pem(&cfg.cert_pem)
        .map_err(|e| anyhow!("客户端证书解析失败：{e}"))?;
    let client_key =
        load_key_from_pem(&cfg.key_pem).map_err(|e| anyhow!("客户端私钥解析失败：{e}"))?;
    let tls_config = create_client_config(ca, Some((client_certs, client_key)))
        .map_err(|e| anyhow!("TLS 配置构造失败：{e}"))?;
    let name = cfg.sni.clone().unwrap_or_else(|| cfg.server.clone());
    let server_name = if name.parse::<std::net::IpAddr>().is_ok() {
        // IP 字面量非合法 DNS 名：载具核验器忽略 server_name，回落固定标签
        rustls::pki_types::ServerName::try_from("openvpn-server".to_string())
            .context("server_name 构造失败")?
    } else {
        rustls::pki_types::ServerName::try_from(name).context("server_name 构造失败")?
    };
    TlsClientHandler::new(tls_config, server_name).map_err(|e| anyhow!("TLS 处理器构造失败：{e}"))
}

/// 会话建立：UDP 传输 + 完整握手 + 密钥派生 + PUSH_REPLY → 栈参数。
///
/// 返回（UDP 套接字、就绪会话、三层桥参数）——驱动循环接管前两者。
async fn establish_session(
    cfg: &OpenVpnConfig,
) -> Result<(UdpSocket, ProtocolSession, TunnelInfo)> {
    let cipher_suite = cipher_suite_of(&cfg.cipher)?;

    let remote: std::net::SocketAddr = if cfg.server.parse::<Ipv4Addr>().is_ok() {
        format!("{}:{}", cfg.server, cfg.port)
            .parse()
            .context("服务器地址非法")?
    } else {
        return Err(anyhow!(
            "openvpn 服务器须为 IPv4 字面量（隧道外 DNS 自举面未交付）：{}",
            cfg.server
        ));
    };
    let mut socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("UDP 绑定失败")?;
    socket.connect(remote).await.context("UDP 连接失败")?;

    let mut session = ProtocolSession::new_client(cipher_suite);
    if let Some(ref ta) = cfg.tls_auth_key {
        let ta_key: [u8; 256] = ta[..256.min(ta.len())]
            .try_into()
            .map_err(|_| anyhow!("tls-auth 密钥须 256 字节"))?;
        let auth = HmacAuth::from_ta_key(&ta_key, false, cfg.key_direction)
            .map_err(|e| anyhow!("tls-auth 密钥构造失败：{e}"))?;
        session.set_tls_auth(auth);
    }

    // 硬复位 → 服务端硬复位应答 → ACK
    let hard_reset = session
        .create_hard_reset_client()
        .map_err(|e| anyhow!("硬复位包构造失败：{e}"))?;
    socket.send(&hard_reset).await?;
    let mut buf = vec![0u8; RECV_BUF];
    tokio::time::timeout(
        Duration::from_secs(10),
        recv_until(&mut socket, &mut session, &mut buf, |p| {
            matches!(p, ProcessedPacket::HardResetAck)
        }),
    )
    .await
    .map_err(|_| anyhow!("等待服务端硬复位应答超时"))??;
    if let Some(ack) = session.create_ack_packet() {
        socket.send(&ack).await?;
    }

    // TLS 握手（ClientHello 先行）
    let mut tls = setup_tls_client(cfg)?;
    let hello = tls
        .get_outgoing()
        .map_err(|e| anyhow!("ClientHello 取出失败：{e}"))?
        .context("无 ClientHello 数据")?;
    for pkt in session
        .create_control_packets(hello)
        .map_err(|e| anyhow!("ClientHello 控制包构造失败：{e}"))?
    {
        socket.send(&pkt).await?;
    }

    // KeyMethodV2 预生成（与 TLS Finished 同批冲刷）
    let pre_master: [u8; 48] = random_bytes();
    let client_random1: [u8; 32] = random_bytes();
    let client_random2: [u8; 32] = random_bytes();
    let client_km = KeyMethodV2 {
        pre_master,
        random1: client_random1,
        random2: client_random2,
        options: format!(
            "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto UDPv4,cipher {},auth [null-digest],keysize 256,key-method 2,tls-client",
            cfg.cipher
        ),
        username: None,
        password: None,
        peer_info: Some(PEER_INFO.to_string()),
    };
    let km_bytes = client_km.encode(false);

    // TLS 握手循环
    let mut handshake_complete = false;
    let mut attempts = 0;
    while !handshake_complete {
        attempts += 1;
        if attempts > MAX_HANDSHAKE_ATTEMPTS {
            bail!("TLS 握手失败：迭代超限");
        }
        let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow!("TLS 握手收包超时"))?
            .context("TLS 握手收包失败")?;
        let result = session
            .process_packet(&buf[..n])
            .map_err(|e| anyhow!("TLS 握手报文处理失败：{e}"))?;
        match result {
            ProcessedPacket::TlsData(records) => {
                tls.process_tls_records(records)
                    .map_err(|e| anyhow!("TLS 处理失败：{e}"))?;
                send_acks_and_retransmits(&mut socket, &mut session).await;
                if tls.is_handshake_complete() {
                    session.set_state(ProtocolState::KeyExchange);
                    tls.write_plaintext(&km_bytes)
                        .map_err(|e| anyhow!("KeyMethodV2 写入失败：{e}"))?;
                    flush_tls(&mut socket, &mut session, &mut tls).await?;
                    handshake_complete = true;
                } else {
                    flush_tls(&mut socket, &mut session, &mut tls).await?;
                }
            }
            ProcessedPacket::None => {
                send_acks_and_retransmits(&mut socket, &mut session).await;
            }
            _ => {
                send_acks_and_retransmits(&mut socket, &mut session).await;
            }
        }
    }

    // KeyMethodV2 + PUSH_REPLY 交换
    let mut plaintext_buf = vec![0u8; 8192];
    let mut total_plaintext: Vec<u8> = Vec::new();
    let mut server_km: Option<KeyMethodV2> = None;
    let mut push_reply: Option<PushReply> = None;
    let mut km_attempts = 0;
    while push_reply.is_none() {
        km_attempts += 1;
        if km_attempts > MAX_KM_ATTEMPTS {
            bail!("等待服务端密钥交换与 PUSH_REPLY 超时");
        }
        let n = tls
            .read_plaintext(&mut plaintext_buf)
            .map_err(|e| anyhow!("TLS 读失败：{e}"))?;
        if n > 0 {
            total_plaintext.extend_from_slice(&plaintext_buf[..n]);
            try_parse_server_messages(&mut total_plaintext, &mut server_km, &mut push_reply)?;
            if push_reply.is_some() {
                break;
            }
            continue;
        }
        let recv = tokio::time::timeout(Duration::from_secs(30), socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow!("密钥交换收包超时"))?
            .context("密钥交换收包失败")?;
        let result = session
            .process_packet(&buf[..recv])
            .map_err(|e| anyhow!("密钥交换报文处理失败：{e}"))?;
        match result {
            ProcessedPacket::TlsData(records) => {
                tls.process_tls_records(records)
                    .map_err(|e| anyhow!("TLS 处理失败：{e}"))?;
                send_acks_and_retransmits(&mut socket, &mut session).await;
                flush_tls(&mut socket, &mut session, &mut tls).await?;
            }
            _ => {
                send_acks_and_retransmits(&mut socket, &mut session).await;
            }
        }
    }

    let server_km = server_km.context("未收到服务端 KeyMethodV2")?;
    let push_reply = push_reply.expect("push_reply 在循环退出时非空");

    // PRF 密钥派生（master_secret → key_block → 安装）
    let client_sid = *session.local_session_id();
    let server_sid = session
        .remote_session_id()
        .copied()
        .context("缺服务端会话 id")?;
    let mut seed1 = Vec::with_capacity(64);
    seed1.extend_from_slice(&client_random1);
    seed1.extend_from_slice(&server_km.random1);
    let master_secret = openvpn_prf(&pre_master, b"OpenVPN master secret", &seed1, 48)
        .map_err(|e| anyhow!("PRF master secret 失败：{e}"))?;
    let mut seed2 = Vec::with_capacity(80);
    seed2.extend_from_slice(&client_random2);
    seed2.extend_from_slice(&server_km.random2);
    seed2.extend_from_slice(&client_sid);
    seed2.extend_from_slice(&server_sid);
    let key_block = openvpn_prf(&master_secret, b"OpenVPN key expansion", &seed2, 256)
        .map_err(|e| anyhow!("PRF key expansion 失败：{e}"))?;
    let km = KeyMaterial::from_openvpn_key2_block(&key_block);
    session.install_keys(&km, false);
    session.set_state(ProtocolState::Established);

    let mtu = tun_mtu_of(&server_km.options);
    let info = tunnel_info_from(&push_reply, mtu)?;
    Ok((socket, session, info))
}

/// 数据面驱动循环：独占 UDP 读写与会话状态。下行 Data 入栈；PING 原样
/// 回；ACK/重传按载具语义补发；密码学/传输破裂 → 会话终止面（dead 置位
/// + abort 全部活跃流）。上行栈出包逐包加密发出；周期性客户端 PING 保活。
async fn drive_session(
    stack: std::sync::Arc<EgressStack>,
    dead: std::sync::Arc<AtomicBool>,
    ping_secs: u64,
    mut socket: UdpSocket,
    mut session: ProtocolSession,
) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    let ping_period = Duration::from_secs(ping_secs.max(1));
    let mut ping = tokio::time::interval(ping_period);
    ping.tick().await; // 首跳立即返回（tokio interval 语义），不立刻发 PING
    let mut running = true;
    while running {
        tokio::select! {
            r = socket.recv(&mut buf) => {
                match r {
                    Ok(0) | Err(_) => running = false,
                    Ok(n) => match session.process_packet(&buf[..n]) {
                        Ok(ProcessedPacket::Data(dec)) => {
                            if dec.len() == PING_PAYLOAD.len() && dec.as_ref() == PING_PAYLOAD {
                                // PING 原样回（非 IP 包，不入栈）
                                if let Ok(enc) = session.encrypt_data(&PING_PAYLOAD) {
                                    let _ = socket.send(&enc).await;
                                }
                            } else {
                                stack.ingest(dec.to_vec());
                            }
                        }
                        Ok(ProcessedPacket::None) | Ok(ProcessedPacket::TlsData(_)) => {
                            send_acks_and_retransmits(&mut socket, &mut session).await;
                        }
                        Ok(_) => {}
                        Err(_) => running = false,
                    },
                }
            }
            _ = stack.kick_notify().notified() => {}
            _ = tick.tick() => {}
            _ = ping.tick() => {
                if let Ok(enc) = session.encrypt_data(&PING_PAYLOAD) {
                    let _ = socket.send(&enc).await;
                }
            }
        }
        if running {
            for pkt in stack.drive() {
                if let Ok(enc) = session.encrypt_data(&pkt) {
                    if socket.send(&enc).await.is_err() {
                        running = false;
                        break;
                    }
                }
            }
        }
    }
    dead.store(true, AtomicOrdering::Release);
    stack.shutdown_all();
    stack.kick_notify().notify_one();
}

/// 已建立的会话（栈 + 驱动循环句柄）。
struct OpenVpnSession {
    stack: std::sync::Arc<EgressStack>,
    dead: std::sync::Arc<AtomicBool>,
    _driver: tokio::task::JoinHandle<()>,
}

impl OpenVpnSession {
    fn is_dead(&self) -> bool {
        self.dead.load(AtomicOrdering::Acquire)
    }
}

impl Drop for OpenVpnSession {
    fn drop(&mut self) {
        self._driver.abort();
    }
}

/// OpenVPN 出口连接器（RIL-122，库承载 corevpn-protocol 0.6.0）。
///
/// 每节点一条 OpenVPN 会话（惰性建立，断链后下一条流重建）；应用流骑
/// 用户态 smoltcp 栈（三层桥，与 OpenConnect 连接器共用）。仅交付 TCP
/// 应用面（UDP/QUIC 应用面不交付——catalog udp=false 同口径，构建期由
/// scan_udp_capability 拒绝）。
pub struct OpenVpnConnector {
    cfg: OpenVpnConfig,
    session: tokio::sync::Mutex<Option<std::sync::Arc<OpenVpnSession>>>,
}

impl OpenVpnConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: String,
        port: u16,
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
        cipher: String,
        tls_auth_key: Option<Vec<u8>>,
        key_direction: Option<u8>,
        sni: Option<String>,
    ) -> Result<Self> {
        if server.trim().is_empty() {
            return Err(anyhow!("openvpn 服务器地址为空"));
        }
        if ca_pem.trim().is_empty() {
            return Err(anyhow!("openvpn CA 证书缺失（ca_pem 必填——载具根库非空硬要求）"));
        }
        if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
            return Err(anyhow!("openvpn 客户端证书/私钥缺失（cert_pem/key_pem 均必填）"));
        }
        // 密码白名单建期校验（白名单外具名拒绝）
        cipher_suite_of(&cipher)?;
        if let Some(dir) = key_direction {
            if dir > 1 {
                return Err(anyhow!("openvpn tls-auth key-direction 非法：{dir}（合法 0/1）"));
            }
        }
        if server.parse::<Ipv4Addr>().is_err() {
            return Err(anyhow!(
                "openvpn 服务器须为 IPv4 字面量（隧道外 DNS 自举面未交付）：{server}"
            ));
        }
        Ok(Self {
            cfg: OpenVpnConfig {
                server,
                port,
                ca_pem,
                cert_pem,
                key_pem,
                cipher,
                tls_auth_key,
                key_direction,
                sni,
            },
            session: tokio::sync::Mutex::new(None),
        })
    }

    /// 取共享会话（死会话丢弃重建；Mutex 串行化建立——避免并发流重复建隧道）。
    async fn session(&self) -> Result<std::sync::Arc<OpenVpnSession>> {
        let mut slot = self.session.lock().await;
        if let Some(s) = slot.as_ref() {
            if !s.is_dead() {
                return Ok(s.clone());
            }
        }
        let (socket, session, info) =
            tokio::time::timeout(CONNECT_TIMEOUT, establish_session(&self.cfg))
                .await
                .map_err(|_| anyhow!("OpenVPN 会话建立超时（{CONNECT_TIMEOUT:?}）"))?
                .context("OpenVPN 会话建立失败")?;
        let ping_secs = 30; // 客户端保活 PING 周期（服务端 ping-restart 远大于此）
        let stack = std::sync::Arc::new(EgressStack::new(&info));
        let dead = std::sync::Arc::new(AtomicBool::new(false));
        let driver = tokio::spawn(drive_session(
            stack.clone(),
            dead.clone(),
            ping_secs,
            socket,
            session,
        ));
        let s = std::sync::Arc::new(OpenVpnSession {
            stack,
            dead,
            _driver: driver,
        });
        *slot = Some(s.clone());
        Ok(s)
    }
}

#[async_trait::async_trait]
impl rillane_core::EgressConnector for OpenVpnConnector {
    fn name(&self) -> &'static str {
        "openvpn"
    }

    async fn forward(&self, mut flow: rillane_core::Flow) -> Result<rillane_core::FlowReport> {
        use rillane_core::{FlowReport, TargetProto};
        if !matches!(flow.target.proto, TargetProto::Tcp) {
            return Err(anyhow!("OpenVPN 仅交付 TCP 应用面（UDP/QUIC 应用面不交付）"));
        }
        let session = self.session().await?;
        let remote = match flow.target.host.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                use smoltcp::wire::{IpAddress, IpEndpoint};
                IpEndpoint::new(IpAddress::from(std::net::IpAddr::V4(ip)), flow.target.port)
            }
            Err(_) => {
                if flow.target.host.parse::<std::net::Ipv6Addr>().is_ok() {
                    return Err(anyhow!(
                        "OpenVPN 隧道仅 IPv4（ipv4 面），IPv6 目标不支持：{}",
                        flow.target.host
                    ));
                }
                let addrs = session.stack.dns_query(&flow.target.host).await?;
                let ip = addrs
                    .first()
                    .copied()
                    .ok_or_else(|| anyhow!("DNS 无结果：{}", flow.target.host))?;
                use smoltcp::wire::{IpAddress, IpEndpoint};
                IpEndpoint::new(IpAddress::from(std::net::IpAddr::V4(ip)), flow.target.port)
            }
        };
        let handle = session.stack.open_tcp(remote)?;
        session
            .stack
            .wait_established(handle, Duration::from_secs(15))
            .await
            .context("目标连接建立失败")?;
        let mut stream = EgressTcpStream::new(session.stack.clone(), handle);
        let (up, down) = tokio::io::copy_bidirectional(&mut flow.io, &mut stream)
            .await
            .map_err(|e| anyhow!("relay 失败：{e}"))?;
        Ok(FlowReport {
            upstream: up,
            downstream: down,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_whitelist() {
        assert!(cipher_suite_of("AES-256-GCM").is_ok());
        assert!(cipher_suite_of("aes-256-gcm").is_ok());
        assert!(cipher_suite_of("CHACHA20-POLY1305").is_ok());
        let err = cipher_suite_of("AES-128-CBC").err().unwrap().to_string();
        assert!(err.contains("白名单"), "具名拒绝：{err}");
    }

    #[test]
    fn tun_mtu_parsing() {
        assert_eq!(
            tun_mtu_of("V4,dev-type tun,link-mtu 1553,tun-mtu 1500,proto UDPv4,auth SHA256,keysize 128,key-method 2,tls-server"),
            1500
        );
        assert_eq!(tun_mtu_of("V4,tun-mtu 1400"), 1400);
        assert_eq!(tun_mtu_of("V4"), 1500);
        assert_eq!(tun_mtu_of("tun-mtu 70000"), 1500); // 越界回落缺省
    }

    #[test]
    fn km_size_calculation() {
        // 定长 69 + options 串 + 空 username/password
        let opts = b"V4,dev-type tun,tls-server";
        let mut data = vec![0u8; 69];
        data.extend_from_slice(&(opts.len() as u16).to_be_bytes());
        data.extend_from_slice(opts);
        data.extend_from_slice(&0u16.to_be_bytes()); // username 空
        data.extend_from_slice(&0u16.to_be_bytes()); // password 空
        assert_eq!(calculate_km_size(&data).unwrap(), data.len());
        // 过短具名
        assert!(calculate_km_size(&[0u8; 10]).is_err());
    }

    #[test]
    fn connector_rejects_missing_inputs() {
        assert!(OpenVpnConnector::new(
            "".into(),
            1194,
            "CA".into(),
            "C".into(),
            "K".into(),
            "AES-256-GCM".into(),
            None,
            None,
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("服务器地址为空"));
        assert!(OpenVpnConnector::new(
            "127.0.0.1".into(),
            1194,
            "".into(),
            "C".into(),
            "K".into(),
            "AES-256-GCM".into(),
            None,
            None,
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("CA 证书缺失"));
        assert!(OpenVpnConnector::new(
            "127.0.0.1".into(),
            1194,
            "CA".into(),
            "".into(),
            "K".into(),
            "AES-256-GCM".into(),
            None,
            None,
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("证书/私钥缺失"));
        assert!(OpenVpnConnector::new(
            "127.0.0.1".into(),
            1194,
            "CA".into(),
            "C".into(),
            "K".into(),
            "AES-128-CBC".into(),
            None,
            None,
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("白名单"));
        assert!(OpenVpnConnector::new(
            "vpn.example.test".into(),
            1194,
            "CA".into(),
            "C".into(),
            "K".into(),
            "AES-256-GCM".into(),
            None,
            None,
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("IPv4 字面量"));
        assert!(OpenVpnConnector::new(
            "127.0.0.1".into(),
            1194,
            "CA".into(),
            "C".into(),
            "K".into(),
            "AES-256-GCM".into(),
            Some(vec![0u8; 300]),
            Some(5),
            None,
        )
        .err().unwrap()
        .to_string()
        .contains("key-direction 非法"));
    }
}
