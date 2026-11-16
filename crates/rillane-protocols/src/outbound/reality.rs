//! REALITY 传输面（RIL-107）：xray REALITY 语义的 rustls fork（cfal/rustls
//! rev d17d0fc3）装配。选库与角色边界见 docs/zh/protocol-backends.md#vless：
//! fork 的 REALITY 面显式不认证对端——认证由本模块实现：
//!
//! - 认证 ECDH：客户端认证临时密钥即 TLS key share（x25519），与节点
//!   静态公钥做 ECDH 得 shared secret（与 Xray `KeyShareKeys.Ecdhe` 同构）
//! - auth_key = HKDF-SHA256(ikm=shared, salt=ClientRandom[..20], info="REALITY")
//! - session-id = AES-256-GCM(auth_key).seal(pt16, nonce=ClientRandom[20..],
//!   aad=ClientHello session-id 槽置零)；pt16 = 版本(1,26,3)+0+时间戳 u32 BE
//!   + short_id ≤8 字节零填充
//! - 服务端证明 = HMAC 证书：leaf 证书签名字段 = HMAC-SHA512(auth_key,
//!   ed25519 公钥)——只有能打开 session-id 的服务端（持有静态私钥）能产出；
//!   客户端 CertificateVerify 以该 ed25519 私钥真签（校验防证书/签名错配）
//!
//! 记录层填充仅 aws_lc_rs provider 实现（ring 默认实现拒绝非零填充），
//! REALITY 连接显式传入 aws_lc_rs provider、kx_groups 仅 X25519。

use std::io::{self, BufRead as _, Write as _};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::reality::ClientHooks;
use rustls::{ClientConfig, ClientConnection, ConnectionCommon, Error, NamedGroup, SideData};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};
use x509_parser::prelude::FromDer;

use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

/// session-id 明文的 REALITY 核心版本三元组（Xray core (1, 26, 3) 口径）
pub const CORE_VERSION: (u8, u8, u8) = (1, 26, 3);

/// ClientHello（无记录头）中 session-id 槽位：[38] 长度字节（=32），[39..71] 载荷
const SESSION_ID_SLOT: std::ops::Range<usize> = 39..71;

// ---------------------------------------------------------------------------
// 认证原语（xray REALITY 线格式；服务端真实对端同用这一组）
// ---------------------------------------------------------------------------

/// auth_key = HKDF-SHA256(ikm=认证 ECDH shared, salt=ClientRandom[..20], info="REALITY")
pub fn derive_auth_key(shared: &[u8; 32], random_salt_20: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(random_salt_20), shared);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .expect("32 字节是 HKDF-SHA256 合法输出长度");
    auth_key
}

/// HMAC-SHA512(auth_key, ed25519 公钥) —— REALITY HMAC 证书的「签名」载荷
pub fn hmac_cert_tag(auth_key: &[u8; 32], ed25519_public: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("HMAC 接受 32 字节密钥");
    mac.update(ed25519_public);
    mac.finalize().into_bytes().into()
}

/// ClientHello 的 session-id 槽置零副本（seal/open 双侧 AAD 口径；Xray
/// `copy(hello.Raw[39:], hello.SessionId)` 零填充占位等价）
pub fn zero_session_id_slot(hello: &[u8]) -> Vec<u8> {
    let mut aad = hello.to_vec();
    if aad.len() >= SESSION_ID_SLOT.end {
        aad[SESSION_ID_SLOT.clone()].fill(0);
    }
    aad
}

/// 读取 ClientHello 的 ClientRandom（无记录头：[6..38]）
pub fn extract_client_random(hello: &[u8]) -> io::Result<[u8; 32]> {
    if hello.len() < 38 || hello[0] != 1 {
        return Err(bad_hello());
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&hello[6..38]);
    Ok(random)
}

/// 读取 ClientHello 的 32 字节 session-id（[39..71]）
pub fn extract_session_id(hello: &[u8]) -> io::Result<[u8; 32]> {
    if hello.len() < SESSION_ID_SLOT.end || hello[38] != 32 {
        return Err(bad_hello());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&hello[SESSION_ID_SLOT.clone()]);
    Ok(id)
}

/// 从 ClientHello 扩展区提取首个 x25519 key share（认证 ECDH 客户端公钥）。
/// rillane REALITY 客户端 kx_groups 仅 X25519——恰一个 share，无 GREASE 干扰。
pub fn extract_x25519_key_share(hello: &[u8]) -> io::Result<[u8; 32]> {
    let mut pos = 39 + hello.get(38).copied().ok_or_else(bad_hello)? as usize;
    let u16_at = |p: usize, h: &[u8]| -> io::Result<usize> {
        Ok(u16::from_be_bytes(
            h.get(p..p + 2)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(bad_hello)?,
        ) as usize)
    };
    // cipher_suites
    let suites = u16_at(pos, hello)?;
    pos += 2 + suites;
    // compression_methods（u8 长度）
    let comps = *hello.get(pos).ok_or_else(bad_hello)? as usize;
    pos += 1 + comps;
    // extensions 总长
    let _ext_total = u16_at(pos, hello)?;
    pos += 2;

    while pos + 4 <= hello.len() {
        let typ = u16_at(pos, hello)?;
        let len = u16_at(pos + 2, hello)?;
        let body = pos + 4;
        if body + len > hello.len() {
            return Err(bad_hello());
        }
        if typ == 51 {
            // key_share：client_shares_len(2) → entry: group(2) klen(2) key[..]
            let mut e = body + 2;
            let end = body + len;
            while e + 4 <= end {
                let group = u16_at(e, hello)?;
                let klen = u16_at(e + 2, hello)?;
                if group == 0x001d && klen == 32 && e + 4 + 32 <= end {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&hello[e + 4..e + 4 + 32]);
                    return Ok(key);
                }
                e += 4 + klen;
            }
            return Err(bad_hello());
        }
        pos = body + len;
    }
    Err(bad_hello())
}

/// 服务端 open 出的 session 明文（版本/时间戳/short_id）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityAuthSession {
    pub version: (u8, u8, u8),
    pub timestamp: u32,
    pub short_id: [u8; 8],
}

/// AES-256-GCM session-id seal：pt16 = 版本+0+时间戳+short_id（零填充），
/// nonce = ClientRandom[20..32]，AAD = ClientHello 槽置零副本
pub fn seal_session_id(
    auth_key: &[u8; 32],
    nonce_12: &[u8],
    version: (u8, u8, u8),
    timestamp: u32,
    short_id: &[u8],
    aad: &[u8],
) -> io::Result<[u8; 32]> {
    if short_id.len() > 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY short-id 超过 8 字节",
        ));
    }
    let mut pt = [0u8; 16];
    pt[0] = version.0;
    pt[1] = version.1;
    pt[2] = version.2;
    pt[3] = 0; // 保留位（Xray 口径）
    pt[4..8].copy_from_slice(&timestamp.to_be_bytes());
    pt[8..8 + short_id.len()].copy_from_slice(short_id);

    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "REALITY 密钥长度非法"))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce_12), Payload { msg: &pt, aad })
        .map_err(gcm_err)?;
    let sealed: [u8; 32] = ct.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY session-id 密文应为 32 字节",
        )
    })?;
    Ok(sealed)
}

/// AES-256-GCM session-id open（失败 = 认证失败：静钥不符/改写/重放载荷不完整）
pub fn open_session_id(
    auth_key: &[u8; 32],
    nonce_12: &[u8],
    sealed: &[u8; 32],
    aad: &[u8],
) -> io::Result<RealityAuthSession> {
    let cipher = Aes256Gcm::new_from_slice(auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "REALITY 密钥长度非法"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce_12), Payload { msg: sealed, aad })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY session-id 认证失败",
            )
        })?;
    if pt.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY session-id 明文应为 16 字节",
        ));
    }
    Ok(RealityAuthSession {
        version: (pt[0], pt[1], pt[2]),
        timestamp: u32::from_be_bytes([pt[4], pt[5], pt[6], pt[7]]),
        short_id: pt[8..16].try_into().expect("8 字节 short_id"),
    })
}

fn bad_hello() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "非法的 REALITY ClientHello")
}

fn gcm_err(_e: aes_gcm::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "REALITY AES-GCM 运算失败")
}

fn now_unix_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 客户端 hooks / KX / 证书校验
// ---------------------------------------------------------------------------

/// 单连接共享状态（session_id hook 写入 auth_key，证书校验读取）。
/// Debug 不携带密钥材料（fork 的 ClientHooks 约定）。
#[derive(Default)]
struct RealityClientState {
    auth_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for RealityClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClientState")
            .field("auth_key_set", &self.auth_key.is_some())
            .finish()
    }
}

/// 认证临时密钥 = TLS key share（fork 要求返回的 group 与请求一致）。
/// complete 时做 TLS ECDH；认证 ECDH（对静态公钥）在 session_id hook 用
/// 同一密钥的另一份引用完成（StaticSecret 可 Clone）。
struct RealityKeyExchange {
    secret: StaticSecret,
    public: PublicKey,
    group: &'static dyn SupportedKxGroup,
}

impl ActiveKeyExchange for RealityKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let bytes: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::General("REALITY: 非法 key share 长度".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(bytes));
        if !shared.was_contributory() {
            return Err(Error::General("REALITY: 弱 key share".into()));
        }
        Ok(SharedSecret::from(shared.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        self.group.name()
    }
}

/// REALITY 客户端 hooks：start_key_exchange 产出认证临时密钥（=TLS key
/// share）；session_id 以 auth_key 封装真实认证载荷；server_hello 捕获
/// 双 hello（记录用途）。
pub struct RealityClientHooks {
    server_static: PublicKey,
    short_id: [u8; 8],
    ephemeral: Option<StaticSecret>,
    state: Arc<Mutex<RealityClientState>>,
}

impl std::fmt::Debug for RealityClientHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClientHooks")
            .field("short_id", &hex_encode(&self.short_id))
            .finish_non_exhaustive()
    }
}

impl RealityClientHooks {
    fn new(
        server_static: PublicKey,
        short_id: [u8; 8],
        state: Arc<Mutex<RealityClientState>>,
    ) -> Self {
        Self {
            server_static,
            short_id,
            ephemeral: None,
            state,
        }
    }
}

impl ClientHooks for RealityClientHooks {
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // REALITY 认证绑定 x25519（对静态公钥的 ECDH 面即此群）
        if group.name() != NamedGroup::X25519 {
            return Err(Error::General("REALITY: key exchange 须为 x25519".into()));
        }
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        self.ephemeral = Some(secret.clone());
        let public = PublicKey::from(&secret);
        Ok(Box::new(RealityKeyExchange {
            secret,
            public,
            group,
        }))
    }

    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error> {
        let ephemeral = self
            .ephemeral
            .take()
            .ok_or_else(|| Error::General("REALITY: 无可用认证密钥交换".into()))?;
        let random =
            extract_client_random(hello).map_err(|e| Error::General(format!("REALITY: {e}")))?;
        let shared = ephemeral.diffie_hellman(&self.server_static);
        let auth_key = derive_auth_key(shared.as_bytes(), &random[..20]);
        let aad = zero_session_id_slot(hello);
        let sealed = seal_session_id(
            &auth_key,
            &random[20..32],
            CORE_VERSION,
            now_unix_u32(),
            &self.short_id,
            &aad,
        )
        .map_err(|e| Error::General(format!("REALITY: {e}")))?;
        if let Ok(mut st) = self.state.lock() {
            st.auth_key = Some(auth_key);
        }
        Ok(sealed)
    }

    fn server_hello(&mut self, _client: &[u8], _server: &[u8]) -> Result<(), Error> {
        // 服务端证明由证书校验面完成（HMAC 绑定）；此处保留 hook 面以应 fork
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// REALITY 证书校验：leaf 证书签名字段 = HMAC-SHA512(auth_key, ed25519 公钥)
/// （服务端证明）；CertificateVerify 以该 ed25519 私钥真签（本 verifier 显式
/// 验证，防「证书 HMAC 真、握手签名假」的错配绕过）。REALITY 为 TLS1.3-only。
struct RealityCertVerifier {
    state: Arc<Mutex<RealityClientState>>,
}

impl std::fmt::Debug for RealityCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityCertVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RealityCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 证书链验证被认证模型替代（Xray 口径：被转发到真实目标站点时，
        // 其证书链虽真但无 HMAC 绑定——本路径不信任链，只信 HMAC 绑定）
        let auth_key = self
            .state
            .lock()
            .ok()
            .and_then(|st| st.auth_key)
            .ok_or_else(|| Error::General("REALITY: auth key 未就绪".into()))?;
        verify_hmac_cert(end_entity.as_ref(), &auth_key)
            .map_err(|e| Error::General(format!("REALITY: 服务端证书认证失败: {e}")))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("REALITY: 不支持 TLS1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // CertificateVerify 以证书内 ed25519 公钥真签（防密钥错配）
        if dss.scheme != rustls::SignatureScheme::ED25519 {
            return Err(Error::General("REALITY: 签名方案须为 ed25519".into()));
        }
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
            .map_err(|e| Error::General(format!("REALITY: 证书解析失败: {e}")))?;
        let pub_bytes: &[u8] = &parsed.public_key().subject_public_key.data;
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            pub_bytes
                .try_into()
                .map_err(|_| Error::General("REALITY: 证书公钥须为 32 字节 ed25519".into()))?,
        )
        .map_err(|e| Error::General(format!("REALITY: 公钥非法: {e}")))?;
        let sig = ed25519_dalek::Signature::from_bytes(
            dss.signature()
                .try_into()
                .map_err(|_| Error::General("REALITY: 签名须为 64 字节".into()))?,
        );
        key.verify_strict(message, &sig)
            .map_err(|e| Error::General(format!("REALITY: CertificateVerify 验签失败: {e}")))?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// HMAC 证书校验：签名字段 = HMAC-SHA512(auth_key, ed25519 公钥)，
/// 常时比较（hmac::verify_slice 内建恒时）
fn verify_hmac_cert(der: &[u8], auth_key: &[u8; 32]) -> io::Result<()> {
    let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("证书解析失败: {e}")))?;
    if !rest.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "证书携带尾随字节",
        ));
    }
    let pub_bytes: &[u8] = &cert.public_key().subject_public_key.data;
    let sig: &[u8] = &cert.signature_value.data;
    if pub_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("REALITY 证书公钥须为 32 字节（实际 {}）", pub_bytes.len()),
        ));
    }
    if sig.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("REALITY 证书签名须为 64 字节（实际 {}）", sig.len()),
        ));
    }
    let expect = hmac_cert_tag(auth_key, pub_bytes);
    if expect.ct_eq_constant(sig) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY 服务端证书 HMAC 绑定不符（非真实服务端）",
        ))
    }
}

trait CtEqExt {
    fn ct_eq_constant(&self, other: &[u8]) -> bool;
}

impl CtEqExt for [u8; 64] {
    fn ct_eq_constant(&self, other: &[u8]) -> bool {
        // subtle 恒时比较（Go hmac.Equal 口径）；长度不等即拒绝
        self.as_slice().ct_eq(other).into()
    }
}

// ---------------------------------------------------------------------------
// REALITY 拨号面
// ---------------------------------------------------------------------------

/// REALITY 出站拨号配置（Vless { reality } 的传输面装配体）。
/// 每连接一次完整握手、禁 resumption（fork 口径）——不进传输池。
#[derive(Clone, Debug)]
pub struct RealityDial {
    server_static: PublicKey,
    short_id: [u8; 8],
    alpn: Vec<Vec<u8>>,
}

impl RealityDial {
    /// public_key：节点静态公钥（64 位 hex）；short_id：可选 ≤8 字节 hex
    pub fn new(public_key_hex: &str, short_id_hex: Option<&str>) -> io::Result<Self> {
        let pk = hex_decode_32(public_key_hex).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("REALITY 公钥无效: {e}"),
            )
        })?;
        let short_id = match short_id_hex {
            None | Some("") => [0u8; 8],
            Some(hex) => {
                let bytes = decode_hex(hex).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("REALITY short-id 无效: {e}"),
                    )
                })?;
                if bytes.len() > 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "REALITY short-id 无效: 超过 8 字节",
                    ));
                }
                let mut id = [0u8; 8];
                id[..bytes.len()].copy_from_slice(&bytes);
                id
            }
        };
        Ok(Self {
            server_static: PublicKey::from(pk),
            short_id,
            alpn: Vec::new(),
        })
    }

    /// ALPN 列表（REALITY 面 vless tcp 通常不叠 alpn；保留给 grpc/h2 组合面）
    pub fn with_alpn(mut self, alpn: &[String]) -> Self {
        self.alpn = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// 在已拨 TCP 上完成 REALITY 握手（建连取消在任务丢弃层，与既有 TLS 面同口径）
    pub async fn connect(
        &self,
        tcp: TcpStream,
        server_name: ServerName<'static>,
    ) -> io::Result<RealityStream> {
        // REALITY 连接显式用 aws_lc_rs provider（记录层填充仅其后端实现），
        // 与全局 ring 默认 provider 共存（不影响既有 TLS 面）；kx_groups 仅
        // X25519（认证 ECDH 群，fork 取 kx_groups[0]）
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let state = Arc::new(Mutex::new(RealityClientState::default()));
        let hooks = RealityClientHooks::new(self.server_static, self.short_id, state.clone());
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(reality_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RealityCertVerifier { state }))
            .with_no_client_auth();
        let mut config = config;
        config.alpn_protocols = self.alpn.clone();
        let conn = ClientConnection::new_reality(Arc::new(config), server_name, Box::new(hooks))
            .map_err(reality_err)?;
        handshake(tcp, conn).await
    }
}

fn reality_err(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("REALITY: {e}"))
}

fn decode_hex(s: &str) -> io::Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hex 长度须为偶数",
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("非法 hex: {e}")))
        })
        .collect()
}

fn hex_decode_32(s: &str) -> io::Result<[u8; 32]> {
    let v = decode_hex(s)?;
    v.as_slice()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "须为 32 字节 hex"))
}

// ---------------------------------------------------------------------------
// tokio 适配器：rustls 连接的 AsyncRead/AsyncWrite 面
//（tokio-rustls 不能包装预构建连接——connect_with 只收 ClientConfig；
// ClientConnection::new_reality 产物经此适配器进入 tokio 数据面）
// ---------------------------------------------------------------------------

/// rustls 连接（客户端/服务端面）的适配共性：统一以 ConnectionCommon 操作面
/// 承载（`&mut *self` 解引用即可满足——ClientConnection/ServerConnection 的
/// Deref 目标即各自的 ConnectionCommon）
pub trait RustlsConn: DerefMut + Unpin {
    /// 连接侧数据类型（client::ClientConnectionData / server::ServerConnectionData）
    type Side: SideData;

    /// 以 ConnectionCommon 面操作连接
    fn as_conn(&mut self) -> &mut ConnectionCommon<Self::Side>;
}

impl RustlsConn for ClientConnection {
    type Side = rustls::client::ClientConnectionData;

    fn as_conn(&mut self) -> &mut ConnectionCommon<Self::Side> {
        self
    }
}

impl RustlsConn for rustls::ServerConnection {
    type Side = rustls::server::ServerConnectionData;

    fn as_conn(&mut self) -> &mut ConnectionCommon<Self::Side> {
        self
    }
}

/// 单条 rustls 连接的 tokio 传输适配器（客户端/服务端面通用——服务端真实
/// 对端测试用同一实现）。
pub struct TlsAdapter<C: RustlsConn> {
    tcp: TcpStream,
    conn: C,
    eof: bool,
}

/// 客户端面 REALITY 流（BoxedIo 装配面）
pub type RealityStream = TlsAdapter<ClientConnection>;

impl<C: RustlsConn> TlsAdapter<C> {
    pub fn new(tcp: TcpStream, conn: C) -> Self {
        Self {
            tcp,
            conn,
            eof: false,
        }
    }

    pub fn into_tcp(self) -> TcpStream {
        self.tcp
    }

    /// 写出 rustls 队列中的 TLS 记录
    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncWriteAdapter {
            io: &mut self.tcp,
            cx,
        };
        match self.conn.as_conn().write_tls(&mut adapter) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// 读取 TCP 字节喂入 rustls 并解包
    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncReadAdapter {
            io: &mut self.tcp,
            cx,
        };
        let n = match self.conn.as_conn().read_tls(&mut adapter) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.conn.as_conn().process_new_packets().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("REALITY 记录处理失败: {e}"),
            )
        })?;
        Poll::Ready(Ok(n))
    }

    fn poll_fill_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let mut io_pending = false;
        while !self.eof && self.conn.as_conn().wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => {
                    self.eof = true;
                    break;
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        match self.conn.as_conn().reader().into_first_chunk() {
            Ok(buf) => Poll::Ready(Ok(buf)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // rustls 状态异常的自醒面（tokio-rustls 同口径注释）
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<C: RustlsConn> AsyncRead for TlsAdapter<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let data = std::task::ready!(this.poll_fill_buf(cx))?;
        let amount = buf.remaining().min(data.len());
        buf.put_slice(&data[..amount]);
        this.conn.as_conn().reader().consume(amount);
        Poll::Ready(Ok(()))
    }
}

impl<C: RustlsConn> AsyncWrite for TlsAdapter<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut pos = 0;
        loop {
            let mut would_block = false;
            this.conn
                .as_conn()
                .writer()
                .write(&buf[pos..])
                .map_err(io::Error::other)?;
            while this.conn.as_conn().wants_write() {
                match this.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn
            .as_conn()
            .writer()
            .flush()
            .map_err(io::Error::other)?;
        while this.conn.as_conn().wants_write() {
            if std::task::ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // close_notify → TLS 层干净关闭（对端 reader 见 Ok(0)）
        this.conn.as_conn().send_close_notify();
        while this.conn.as_conn().wants_write() {
            if std::task::ready!(this.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}

/// Async IO 上的 std Read 面（Pending → WouldBlock，喂 read_tls）
struct SyncReadAdapter<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO: AsyncRead + Unpin> io::Read for SyncReadAdapter<'_, '_, IO> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rb = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut rb) {
            Poll::Ready(Ok(())) => Ok(rb.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Async IO 上的 std Write 面（Pending → WouldBlock，供 write_tls）
struct SyncWriteAdapter<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO: AsyncWrite + Unpin> io::Write for SyncWriteAdapter<'_, '_, IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// TLS 握手循环（有界轮次：先冲队出站，再读一段入站）；完成后返回数据面
/// 适配器。客户端/服务端面通用（服务端真实对端测试用同一实现）。
pub async fn handshake<C: RustlsConn>(tcp: TcpStream, mut conn: C) -> io::Result<TlsAdapter<C>> {
    let mut tcp = tcp;
    let mut buf = Vec::with_capacity(16 * 1024);
    loop {
        while conn.as_conn().wants_write() {
            buf.clear();
            let n = conn
                .as_conn()
                .write_tls(&mut buf)
                .map_err(io::Error::other)?;
            if n == 0 {
                break;
            }
            tcp.write_all(&buf[..n]).await?;
        }
        if !conn.as_conn().is_handshaking() {
            break;
        }
        let mut chunk = vec![0u8; 16 * 1024];
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "REALITY 握手期对端关闭连接",
            ));
        }
        conn.as_conn()
            .read_tls(&mut &chunk[..n])
            .map_err(io::Error::other)?;
        conn.as_conn()
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("REALITY: {e}")))?;
    }
    Ok(TlsAdapter::new(tcp, conn))
}

// ---------------------------------------------------------------------------
// 单元测试：认证原语 / AAD 口径 / key share 解析 / 适配器
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::aws_lc_rs;
    use rustls::pki_types::pem::PemObject;

    /// 适配器回环用测试校验器（只验数据面；REALITY 认证面由合约测试覆盖）。
    /// supported_verify_schemes 须非空——ClientHello 的 signature_algorithms
    /// 扩展取自校验器。
    #[derive(Debug)]
    struct AcceptAll;

    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    /// REALITY 形状的普通 rustls 客户端连接（aws_lc_rs + 仅 X25519 群 +
    /// 回环校验器）——适配器数据面与 key share 解析测试共用
    fn plain_reality_shaped_client_conn() -> ClientConnection {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("版本")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth();
        ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").expect("server name"),
        )
        .expect("client conn")
    }

    fn auth_pair() -> (StaticSecret, PublicKey) {
        let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pub = PublicKey::from(&server_secret);
        (server_secret, server_pub)
    }

    /// seal/open 往返 + 版本/时间戳/short_id 明文对账（xray 格式口径）
    #[test]
    fn session_id_roundtrip_and_plaintext_layout() {
        let (_, server_pub) = auth_pair();
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let shared = client_secret.diffie_hellman(&server_pub);
        let auth_key = derive_auth_key(shared.as_bytes(), &[7u8; 20]);

        let aad = b"client-hello-bytes-with-zeroed-slot";
        let sealed = seal_session_id(
            &auth_key,
            &[9u8; 12],
            CORE_VERSION,
            1_700_000_000,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            aad,
        )
        .expect("seal");
        let opened = open_session_id(&auth_key, &[9u8; 12], &sealed, aad).expect("open");
        assert_eq!(opened.version, CORE_VERSION);
        assert_eq!(opened.timestamp, 1_700_000_000);
        assert_eq!(
            opened.short_id,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    /// 短 short_id 零填充到 8 字节（服务器可开局比对）
    #[test]
    fn short_short_id_zero_padded() {
        let (_, server_pub) = auth_pair();
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let auth_key = derive_auth_key(
            client_secret.diffie_hellman(&server_pub).as_bytes(),
            &[1u8; 20],
        );
        let sealed = seal_session_id(
            &auth_key,
            &[2u8; 12],
            CORE_VERSION,
            5,
            &[0xab, 0xcd],
            b"aad",
        )
        .expect("seal");
        let opened = open_session_id(&auth_key, &[2u8; 12], &sealed, b"aad").expect("open");
        assert_eq!(&opened.short_id[..2], &[0xab, 0xcd]);
        assert!(opened.short_id[2..].iter().all(|b| *b == 0));
    }

    /// 错误静钥（公钥不符）→ open 认证失败（GCM 拒绝）
    #[test]
    fn open_fails_with_wrong_static_key() {
        let (_, server_pub) = auth_pair();
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let auth_key = derive_auth_key(
            client_secret.diffie_hellman(&server_pub).as_bytes(),
            &[3u8; 20],
        );
        let sealed =
            seal_session_id(&auth_key, &[4u8; 12], CORE_VERSION, 6, &[0xaa], b"aad").expect("seal");
        let other = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let other_key = derive_auth_key(
            client_secret
                .diffie_hellman(&PublicKey::from(&other))
                .as_bytes(),
            &[3u8; 20],
        );
        let err =
            open_session_id(&other_key, &[4u8; 12], &sealed, b"aad").expect_err("错误静钥必须失败");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    /// AAD 口径：槽置零副本与原 hello 在槽位 differ、其余一致；改 AAD → open 拒绝
    #[test]
    fn aad_slot_zeroing_binds_hello() {
        let hello = vec![1u8; 71];
        let aad = zero_session_id_slot(&hello);
        assert_eq!(aad.len(), hello.len());
        assert!(aad[39..71].iter().all(|b| *b == 0));
        assert_eq!(aad[..39], hello[..39]);

        let (_, server_pub) = auth_pair();
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let auth_key = derive_auth_key(
            client_secret.diffie_hellman(&server_pub).as_bytes(),
            &[5u8; 20],
        );
        let sealed =
            seal_session_id(&auth_key, &[6u8; 12], CORE_VERSION, 7, &[0xbb], &aad).expect("seal");
        // 不同 AAD（未被置零的 hello）→ 认证失败
        let err =
            open_session_id(&auth_key, &[6u8; 12], &sealed, &hello).expect_err("AAD 不符必须失败");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // 相同 AAD → 成功
        open_session_id(&auth_key, &[6u8; 12], &sealed, &aad).expect("open");
    }

    /// key share 解析：用真实 rustls ClientHello（kx 仅 X25519）解析出认证公钥
    #[test]
    fn key_share_parsed_from_real_rustls_hello() {
        let mut client = plain_reality_shaped_client_conn();
        let mut wire = Vec::new();
        client.write_tls(&mut &mut wire).expect("write tls");
        let hello = &wire[5..]; // 去记录头
        assert_eq!(hello[38], 32, "session-id 长度位");
        let random = extract_client_random(hello).expect("random");
        assert_eq!(random.len(), 32);
        extract_session_id(hello).expect("session id");

        // 解析出的 key share 非零（rustls 侧 kx_groups[0] 产的认证公钥）
        let parsed = extract_x25519_key_share(hello).expect("key share");
        assert_ne!(parsed, [0u8; 32], "解析出非零 key share");
    }

    /// HMAC 证书标签：同密钥同公钥一致、密钥变化即不符（证书绑定面）
    #[test]
    fn hmac_cert_tag_binds_key_and_pub() {
        let tag_a = hmac_cert_tag(&[1u8; 32], &[2u8; 32]);
        let tag_b = hmac_cert_tag(&[1u8; 32], &[2u8; 32]);
        assert_eq!(tag_a, tag_b, "同输入同标签");
        let tag_c = hmac_cert_tag(&[9u8; 32], &[2u8; 32]);
        assert_ne!(tag_a, tag_c, "密钥变化标签即变");
    }

    /// 恒时比较面：正确签名通过、篡改签名拒绝（verify_hmac_cert）
    #[test]
    fn hmac_cert_verify_accepts_and_rejects() {
        // 构造最小合法 DER 证书过重：直接走真实 rcgen 证书在合约测试覆盖；
        // 此处覆盖 CtEqExt 面语义
        let tag = hmac_cert_tag(&[1u8; 32], &[2u8; 32]);
        assert!(tag.ct_eq_constant(&tag));
        let mut tampered = tag;
        tampered[0] ^= 1;
        assert!(!tag.ct_eq_constant(&tampered));
    }

    /// RealityDial 配置面：公钥/short-id hex 解析与点名拒绝
    #[test]
    fn dial_config_parses_and_rejects_named() {
        let pk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        RealityDial::new(pk, Some("0102030405060708")).expect("合法配置");
        RealityDial::new(pk, None).expect("无 short-id 合法");
        let err = RealityDial::new("zz", None).expect_err("非法 hex 拒绝");
        assert!(format!("{err}").contains("REALITY 公钥无效"));
        let err = RealityDial::new("abcd", None).expect_err("长度不足拒绝");
        assert!(format!("{err}").contains("REALITY 公钥无效"));
        let err = RealityDial::new(pk, Some("010203040506070809")).expect_err("short-id 超长拒绝");
        assert!(format!("{err}").contains("超过 8 字节"));
    }

    /// 适配器 e2e：普通 rustls 客户端连接经 TlsAdapter 与 tokio TLS 服务端
    /// 回环（数据面/close_notify/EOF 口径——REALITY 握手面由合约测试覆盖）
    #[tokio::test]
    async fn tls_adapter_loopback_roundtrip_and_close() {
        use tokio_rustls::TlsAcceptor;

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
        let provider = Arc::new(aws_lc_rs::default_provider());
        let acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("版本")
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("服务端装配"),
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls = acceptor.accept(tcp).await.expect("accept");
                    let mut buf = Vec::new();
                    let _ = tls.read_to_end(&mut buf).await;
                    let _ = tls.write_all(&buf).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        // 客户端：普通 rustls 连接 + TlsAdapter（与 REALITY 面同一数据面实现）
        let tcp = TcpStream::connect(addr).await.expect("dial");
        let conn = plain_reality_shaped_client_conn();
        let mut stream = handshake(tcp, conn).await.expect("REALITY 握手面复用");

        let payload = b"ril107 adapter roundtrip";
        stream.write_all(payload).await.expect("上行");
        stream.shutdown().await.expect("写关闭（close_notify）");
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.expect("下行");
        assert_eq!(echoed, payload, "适配器回环一致");
    }

    /// 取消面：适配器 forward 进行中丢弃 → close_notify 已发出或 TCP 直接
    /// 关闭——对端 2s 内见连接结束（资源释放）
    #[tokio::test]
    async fn tls_adapter_cancel_releases_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio_rustls::TlsAcceptor;

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
        let provider = Arc::new(aws_lc_rs::default_provider());
        let acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("版本")
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("服务端装配"),
        ));
        let finished = Arc::new(AtomicUsize::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        let fin = finished.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let fin = fin.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        // 读到连接结束（close_notify/EOF/重置）——对端释放可见
                        let mut buf = vec![0u8; 1024];
                        loop {
                            match tls.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        fin.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });

        let tcp = TcpStream::connect(addr).await.expect("dial");
        let conn = plain_reality_shaped_client_conn();
        let mut stream = handshake(tcp, conn).await.expect("握手");
        stream.write_all(b"hello").await.expect("写一段");

        // 丢弃适配器（任务取消语义）→ TCP 关闭 → 服务端读结束可见
        drop(stream);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while finished.load(Ordering::SeqCst) == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "对端 2s 内应见连接结束"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
