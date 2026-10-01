//! TLS 辅助模块

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, HandshakeKind};
use tokio_rustls::TlsConnector;

use crate::fingerprint::TlsFingerprint;

/// 工厂缓存键 = (skip_cert_verify, 规一化 alpn)——与 pool::normalize_alpn 同规整
type FactoryConfigKey = (bool, Vec<String>, TlsFingerprint);
type FactoryConfigCache = HashMap<FactoryConfigKey, Arc<ClientConfig>>;

/// 创建指定指纹形态的 TLS 连接器（P2-5 §4-1 单漏斗：每流路径变形入口，
/// M1 起由连接器透传配置面指纹；`None` 形态 = 存量逐字节行为）
pub fn create_tls_connector_with_profile(
    skip_cert_verify: bool,
    alpn: Option<&[String]>,
    profile: TlsFingerprint,
) -> Result<TlsConnector> {
    let alpn_protos = alpn.map(filter_alpn);
    let config = build_client_config(skip_cert_verify, alpn_protos.unwrap_or_default(), profile)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// ALPN 列表规整（trim + 滤空；对齐既有行为：全空则不设 ALPN）
fn filter_alpn(alpn: &[String]) -> Vec<Vec<u8>> {
    let mut protos = Vec::new();
    for p in alpn {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        protos.push(p.as_bytes().to_vec());
    }
    protos
}

/// 进程级 TLS 密码套件提供方（一次性显式安装）。
///
/// 依赖图特征统一后 rustls 同持 `ring` 与 `aws_lc_rs` 两特征（本仓直依赖
/// 默认 aws-lc-rs，reqwest→hyper-rustls 引入 ring），`ClientConfig::builder()`
/// 在双提供方歧义下直接 panic（rustls crypto/mod.rs）——既有出站 TLS 首拨即崩
/// 的潜在缺陷。此处显式选 ring 并安装为进程默认（已装则尊重既有安装），
/// `build_client_config` 经 `builder_with_provider` 走显式提供方构造。
pub(crate) fn tls_crypto_provider() -> Arc<CryptoProvider> {
    static INSTALL: OnceLock<()> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    CryptoProvider::get_default()
        .expect("tls_crypto_provider 已完成安装")
        .clone()
}

/// 按形态构造 ClientConfig（P2-5 §4-1 单漏斗）：none = 缺省路径逐字节
/// 不动（E2 零差异），其余形态经变形漏斗（fingerprint.rs）。
fn build_client_config(
    skip_cert_verify: bool,
    alpn_protos: Vec<Vec<u8>>,
    profile: TlsFingerprint,
) -> Result<ClientConfig> {
    match profile {
        TlsFingerprint::None => default_client_config(skip_cert_verify, alpn_protos),
        shaped => {
            crate::fingerprint::build_shaped_client_config(skip_cert_verify, alpn_protos, shaped)
        }
    }
}

fn default_client_config(
    skip_cert_verify: bool,
    alpn_protos: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(tls_crypto_provider())
        .with_safe_default_protocol_versions()?;
    let mut config = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    if !alpn_protos.is_empty() {
        config.alpn_protocols = alpn_protos;
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// TlsConnectorFactory（P1-5 D-5，egress-connection-pool.md §2.4）
// ---------------------------------------------------------------------------

/// 进程级共享 `ClientConfig` 工厂：同键（skip_cert_verify + 规一化 alpn）
/// 返回共享 `Arc<ClientConfig>` 的连接器——共享实例上 rustls 默认恢复策略
/// （`Resumption::in_memory_sessions`）的会话缓存跨流存活，TLS 会话恢复
/// 由此生效（每流新建 `ClientConfig` 是恢复失效根因，§2.4 源码核对）。
///
/// `HandshakeKind` 观测（`seep_tls_handshakes_total{type}` 数据源）：
/// 拨号完成侧（池/连接器）读 `handshake_kind()` 后回填 [`Self::note_handshake`]。
pub struct TlsConnectorFactory {
    session_cache_size: usize,
    configs: Mutex<FactoryConfigCache>,
    handshakes_full: AtomicU64,
    handshakes_full_hrr: AtomicU64,
    handshakes_resumed: AtomicU64,
}

impl std::fmt::Debug for TlsConnectorFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnectorFactory")
            .field("session_cache_size", &self.session_cache_size)
            .finish_non_exhaustive()
    }
}

impl TlsConnectorFactory {
    pub fn new(session_cache_size: usize) -> Self {
        Self {
            session_cache_size,
            configs: Mutex::new(HashMap::new()),
            handshakes_full: AtomicU64::new(0),
            handshakes_full_hrr: AtomicU64::new(0),
            handshakes_resumed: AtomicU64::new(0),
        }
    }

    /// 同键共享的 `Arc<ClientConfig>`（异键异实例；`Arc::ptr_eq` 可断言，
    /// §8.1 工厂测试）。显式钉会话缓存容量（§2.4）。
    pub fn shared_config(
        &self,
        skip_cert_verify: bool,
        alpn: &[String],
        fingerprint: TlsFingerprint,
    ) -> Result<Arc<ClientConfig>> {
        let norm = crate::pool::normalize_alpn(alpn);
        let key = (skip_cert_verify, norm, fingerprint);
        if let Some(hit) = self.configs.lock().expect("factory configs lock").get(&key) {
            return Ok(hit.clone());
        }
        let protos = filter_alpn(&key.1);
        let mut config = build_client_config(key.0, protos, key.2)?;
        config.resumption = rustls::client::Resumption::in_memory_sessions(self.session_cache_size);
        let arc = Arc::new(config);
        self.configs
            .lock()
            .expect("factory configs lock")
            .insert(key, arc.clone());
        Ok(arc)
    }

    /// 同键返回共享 `Arc` 的连接器（`TlsConnector::from(Arc<ClientConfig>)`
    /// 为廉价克隆）。
    pub fn connector(
        &self,
        skip_cert_verify: bool,
        alpn: &[String],
        fingerprint: TlsFingerprint,
    ) -> Result<TlsConnector> {
        Ok(TlsConnector::from(self.shared_config(
            skip_cert_verify,
            alpn,
            fingerprint,
        )?))
    }

    /// 拨号完成侧回填握手形态（HandshakeKind 三变体直映，§6.1）
    pub fn note_handshake(&self, kind: Option<HandshakeKind>) {
        match kind {
            Some(HandshakeKind::Full) => {
                self.handshakes_full.fetch_add(1, Ordering::Relaxed);
            }
            Some(HandshakeKind::FullWithHelloRetryRequest) => {
                self.handshakes_full_hrr.fetch_add(1, Ordering::Relaxed);
            }
            Some(HandshakeKind::Resumed) => {
                self.handshakes_resumed.fetch_add(1, Ordering::Relaxed);
            }
            None => {}
        }
    }

    /// `(full, full_hrr, resumed)` 快照
    pub fn handshake_snapshot(&self) -> (u64, u64, u64) {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        (
            g(&self.handshakes_full),
            g(&self.handshakes_full_hrr),
            g(&self.handshakes_resumed),
        )
    }
}

/// 全量签名方案清单（NoVerifier 广告面；P2-5 预设子集的取值域，
/// §5-E5——子集只从此清单收缩，不引入清单外方案）
pub(crate) const FULL_VERIFY_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::ED25519,
];

/// 跳过证书验证的验证器
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        FULL_VERIFY_SCHEMES.to_vec()
    }
}

/// 指纹形态验证器包装（P2-5 D-3）：委托全部校验语义，仅收缩 hello
/// 广告面 `supported_verify_schemes`（清单是广告面非校验面）。
pub(crate) struct ShapedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl std::fmt::Debug for ShapedVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShapedVerifier")
            .field("schemes", &self.schemes)
            .finish_non_exhaustive()
    }
}

impl ShapedVerifier {
    /// 按预设子集排序装配（表值必须 ⊆ [`FULL_VERIFY_SCHEMES`]——构造
    /// 期不查，§7-1 纯函数测试钉住）。
    pub(crate) fn new(
        inner: Arc<dyn ServerCertVerifier>,
        schemes: &[rustls::SignatureScheme],
    ) -> Self {
        Self {
            inner,
            schemes: schemes.to_vec(),
        }
    }
}

impl ServerCertVerifier for ShapedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}
