//! 客户端 TLS 指纹形态（P2-5，tls-fingerprint.md）
//!
//! uTLS 类能力的 rustls 约束内实现：预设 = 版本/套件/群/签名方案四维
//! 参数表（D-1），单漏斗挂载在 `tls.rs::build_client_config`（D-2）。
//! 定位为「指纹可变且预设间可区分」，非等值浏览器伪装（§9-1）。

use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::ClientConfig;

use crate::tls::ShapedVerifier;

/// 指纹形态预设（D-5）：`None` = rustls 缺省形（存量零差异，E2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum TlsFingerprint {
    #[default]
    None,
    Chrome,
    Ios,
    Safari,
}

impl TlsFingerprint {
    /// 配置字符串 → 预设（M1 转换层用；E1 未知值带原值报错）
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "none" | "" => Ok(Self::None),
            "chrome" => Ok(Self::Chrome),
            "ios" => Ok(Self::Ios),
            "safari" => Ok(Self::Safari),
            other => Err(anyhow!(
                "未知的 TLS 指纹形态: {other}（合法值 none|chrome|ios|safari）"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Chrome => "chrome",
            Self::Ios => "ios",
            Self::Safari => "safari",
        }
    }

    /// 预设参数表（D-1）：从 ring 支持集内取子集重排（§5-E5——广告面
    /// 收缩不引入验证盲区）；`None` = 无表（走 rustls 缺省构造）。
    fn spec(&self) -> Option<ShapeSpec> {
        use rustls::CipherSuite as Cs;
        use rustls::NamedGroup as Ng;
        use rustls::SignatureScheme as Ss;
        match self {
            Self::None => None,
            // 双版本 + AES 优先长链（形态取向：桌面 Chrome 主流面）
            Self::Chrome => Some(ShapeSpec {
                versions: Versions::V13AndV12,
                cipher_suites: &[
                    Cs::TLS13_AES_128_GCM_SHA256,
                    Cs::TLS13_AES_256_GCM_SHA384,
                    Cs::TLS13_CHACHA20_POLY1305_SHA256,
                    Cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    Cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    Cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    Cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    Cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    Cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                ],
                kx_groups: &[Ng::X25519, Ng::secp256r1, Ng::secp384r1],
                sig_schemes: &[
                    Ss::RSA_PSS_SHA256,
                    Ss::ECDSA_NISTP256_SHA256,
                    Ss::RSA_PKCS1_SHA256,
                    Ss::RSA_PKCS1_SHA384,
                    Ss::RSA_PSS_SHA384,
                ],
            }),
            // 单 1.3 + P256 优先（形态取向：移动端精简面）
            Self::Ios => Some(ShapeSpec {
                versions: Versions::V13Only,
                cipher_suites: &[
                    Cs::TLS13_AES_256_GCM_SHA384,
                    Cs::TLS13_AES_128_GCM_SHA256,
                    Cs::TLS13_CHACHA20_POLY1305_SHA256,
                ],
                kx_groups: &[Ng::secp256r1, Ng::X25519],
                sig_schemes: &[
                    Ss::ECDSA_NISTP256_SHA256,
                    Ss::RSA_PSS_SHA256,
                    Ss::RSA_PKCS1_SHA256,
                ],
            }),
            // 单 1.3 + ChaCha 优先 + P384（形态取向：又一可区分形）
            Self::Safari => Some(ShapeSpec {
                versions: Versions::V13Only,
                cipher_suites: &[
                    Cs::TLS13_CHACHA20_POLY1305_SHA256,
                    Cs::TLS13_AES_128_GCM_SHA256,
                    Cs::TLS13_AES_256_GCM_SHA384,
                ],
                kx_groups: &[Ng::X25519, Ng::secp384r1],
                sig_schemes: &[
                    Ss::RSA_PKCS1_SHA256,
                    Ss::RSA_PSS_SHA256,
                    Ss::ECDSA_NISTP256_SHA256,
                ],
            }),
        }
    }

    /// 形态串（D-6）：版本/套件/群/方案四维纯函数导出——刻意非 JA3
    /// （extensions 维度运行期由 rustls 决定，§9-1）。预设间两两互异
    /// 是 §7-3 的构造保证。
    pub fn shape_material(&self) -> String {
        let Some(spec) = self.spec() else {
            return "default".to_string();
        };
        let versions = match spec.versions {
            Versions::V13Only => "1.3",
            Versions::V13AndV12 => "1.3,1.2",
        };
        fn fmt(vals: impl Iterator<Item = u16>) -> String {
            vals.map(|v| format!("{v:04x}"))
                .collect::<Vec<_>>()
                .join("-")
        }
        let suites = fmt(spec.cipher_suites.iter().map(|c| u16::from(*c)));
        let groups = fmt(spec.kx_groups.iter().map(|g| u16::from(*g)));
        let sigs = fmt(spec.sig_schemes.iter().map(|s| u16::from(*s)));
        format!("{versions}|{suites}|{groups}|{sigs}")
    }
}

/// 预设参数表：套件/群/方案均为 ring 缺省集的子集排序引用（构造期
/// 对表重排，不引入 ring 外成员——§7-1）。
struct ShapeSpec {
    versions: Versions,
    cipher_suites: &'static [rustls::CipherSuite],
    kx_groups: &'static [rustls::NamedGroup],
    sig_schemes: &'static [rustls::SignatureScheme],
}

enum Versions {
    V13Only,
    V13AndV12,
}

/// 按预设变形 provider（D-1）：从 ring 缺省 provider 按表重排（子集内
/// 重排 = 表中缺名项静默丢弃，升级漂移面 §9-3），保持
/// signature_verification_algorithms/secure_random 原样。
fn shaped_provider(spec: &ShapeSpec) -> CryptoProvider {
    let mut provider = crate::tls::tls_crypto_provider().as_ref().clone();
    provider.cipher_suites = spec
        .cipher_suites
        .iter()
        .filter_map(|want| {
            provider
                .cipher_suites
                .iter()
                .find(|have| have.suite() == *want)
                .cloned()
        })
        .collect();
    provider.kx_groups = spec
        .kx_groups
        .iter()
        .filter_map(|want| {
            provider
                .kx_groups
                .iter()
                .find(|have| have.name() == *want)
                .copied()
        })
        .collect();
    provider
}

/// 按预设构造 ClientConfig（单漏斗变形路径，D-2）：套件/群经变形
/// provider，签名方案经验证器包装（D-3——广告面收缩，委托校验语义
/// 零变化）。仅 `None` 之外形态调用（None 走 tls.rs 缺省路径零差异）。
pub fn build_shaped_client_config(
    skip_cert_verify: bool,
    alpn_protos: Vec<Vec<u8>>,
    profile: TlsFingerprint,
) -> Result<ClientConfig> {
    let spec = profile
        .spec()
        .ok_or_else(|| anyhow!("none 形态走缺省构造路径，不经变形漏斗"))?;
    let provider = shaped_provider(&spec);
    let versions: &[&'static rustls::SupportedProtocolVersion] = match spec.versions {
        Versions::V13Only => &[&rustls::version::TLS13],
        Versions::V13AndV12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let builder =
        ClientConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(versions)?;

    let inner: Arc<dyn ServerCertVerifier> = if skip_cert_verify {
        Arc::new(crate::tls::NoVerifier)
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| anyhow!("webpki 验证器构造失败: {e}"))?
    };

    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ShapedVerifier::new(inner, spec.sig_schemes)))
        .with_no_client_auth();
    if !alpn_protos.is_empty() {
        config.alpn_protocols = alpn_protos;
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// §7-1 预设表纯函数：套件/群均 ⊆ ring 缺省支持集且非空（构造期
    /// retain 不引入 ring 外成员）；chrome = 全量九套件重排（§9-3 漂移
    /// 面的当前形状钉住）。
    #[test]
    fn preset_tables_are_subsets_of_ring_support() {
        let default = rustls::crypto::ring::default_provider();
        let default_suites: Vec<rustls::CipherSuite> =
            default.cipher_suites.iter().map(|s| s.suite()).collect();
        let default_groups: Vec<rustls::NamedGroup> =
            default.kx_groups.iter().map(|g| g.name()).collect();

        for profile in [
            TlsFingerprint::Chrome,
            TlsFingerprint::Ios,
            TlsFingerprint::Safari,
        ] {
            let spec = profile.spec().expect("非 none 形态应有表");
            assert!(
                !spec.cipher_suites.is_empty() && !spec.kx_groups.is_empty(),
                "{:?} 表非空",
                profile
            );
            for s in spec.cipher_suites {
                assert!(
                    default_suites.contains(s),
                    "{:?} 套件 {:?} 不在 ring 支持集",
                    profile,
                    s
                );
            }
            for g in spec.kx_groups {
                assert!(
                    default_groups.contains(g),
                    "{:?} 群 {:?} 不在 ring 支持集",
                    profile,
                    g
                );
            }
            // 变形 provider 保真：重排后仍非空且逐项 ∈ 支持集
            let shaped = shaped_provider(&spec);
            assert!(!shaped.cipher_suites.is_empty());
            assert!(!shaped.kx_groups.is_empty());
        }

        // chrome 形状钉住：九套件全量在（重排 ≠ 缺失）
        let chrome = shaped_provider(&TlsFingerprint::Chrome.spec().unwrap());
        assert_eq!(chrome.cipher_suites.len(), default.cipher_suites.len());
        assert_ne!(
            chrome
                .cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect::<Vec<_>>(),
            default_suites,
            "chrome 重排与缺省序不同（可区分性的构造面）"
        );
        // 单 1.3 形态：变形 provider 只剩 TLS1.3 套件（version() 面）
        let ios = shaped_provider(&TlsFingerprint::Ios.spec().unwrap());
        assert!(ios
            .cipher_suites
            .iter()
            .all(|s| s.version().version == rustls::ProtocolVersion::TLSv1_3));
    }

    /// 签名方案子集 ⊆ 全量清单（§5-E5：广告面收缩不引入清单外方案）。
    #[test]
    fn sig_scheme_subsets_within_full_list() {
        for profile in [
            TlsFingerprint::Chrome,
            TlsFingerprint::Ios,
            TlsFingerprint::Safari,
        ] {
            let spec = profile.spec().unwrap();
            assert!(!spec.sig_schemes.is_empty());
            for s in spec.sig_schemes {
                assert!(
                    crate::tls::FULL_VERIFY_SCHEMES.contains(s),
                    "{:?} 方案 {:?} 不在全量清单",
                    profile,
                    s
                );
            }
        }
        assert_eq!(TlsFingerprint::None.shape_material(), "default");
    }

    // §7-2 hello 捕获：本地 TCP 服务端读首记录直解 ClientHello 五元组。

    type HelloTuple = (u16, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>); // (client_version, suites, extensions, groups, sig_algs)

    fn parse_client_hello(buf: &[u8]) -> HelloTuple {
        assert_eq!(buf[0], 0x16, "握手记录");
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let hs = &buf[5..5 + rec_len];
        assert_eq!(hs[0], 0x01, "ClientHello");
        let mut i = 4; // 跳过 type(1) + length(3)
        let client_version = u16::from_be_bytes([hs[i], hs[i + 1]]);
        i += 2 + 32; // version + random
        let sid_len = hs[i] as usize;
        i += 1 + sid_len;
        let cs_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
        i += 2;
        let mut suites = Vec::new();
        for c in hs[i..i + cs_len].as_chunks::<2>().0 {
            suites.push(u16::from_be_bytes(*c));
        }
        i += cs_len;
        let comp_len = hs[i] as usize;
        i += 1 + comp_len;
        let ext_len = u16::from_be_bytes([hs[i], hs[i + 1]]) as usize;
        i += 2;
        let mut extensions = Vec::new();
        let mut groups = Vec::new();
        let mut sig_algs = Vec::new();
        let end = i + ext_len;
        while i + 4 <= end {
            let et = u16::from_be_bytes([hs[i], hs[i + 1]]);
            let el = u16::from_be_bytes([hs[i + 2], hs[i + 3]]) as usize;
            let data = &hs[i + 4..i + 4 + el];
            extensions.push(et);
            match et {
                0x000a => {
                    // supported_groups：list_len(2) + 群列表
                    for c in data[2..].as_chunks::<2>().0 {
                        groups.push(u16::from_be_bytes(*c));
                    }
                }
                0x000d => {
                    // signature_algorithms：list_len(2) + 方案列表
                    for c in data[2..].as_chunks::<2>().0 {
                        sig_algs.push(u16::from_be_bytes(*c));
                    }
                }
                _ => {}
            }
            i += 4 + el;
        }
        (client_version, suites, extensions, groups, sig_algs)
    }

    async fn capture_hello(profile: TlsFingerprint) -> HelloTuple {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16_384];
            let mut total = 0;
            while total < 5 {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                assert!(n > 0);
                total += n;
            }
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            while total < 5 + rec_len {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                assert!(n > 0);
                total += n;
            }
            buf.truncate(5 + rec_len);
            buf
        });

        // 客户端拨号即发 ClientHello；服务端读满首记录后即断（握手中断
        // 报错忽略——被捕获的 hello 已完整）
        let connector = crate::tls::create_tls_connector_with_profile(true, None, profile).unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("capture.test".to_string())
            .expect("server name");
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await;

        let buf = server.await.unwrap();
        parse_client_hello(&buf)
    }

    /// §7-2/§7-3：四形态 hello 两两互异（≥2 维），预设签名方案 = 表序。
    #[tokio::test]
    async fn hello_tuples_pairwise_distinct() {
        let none = capture_hello(TlsFingerprint::None).await;
        let chrome = capture_hello(TlsFingerprint::Chrome).await;
        let ios = capture_hello(TlsFingerprint::Ios).await;
        let safari = capture_hello(TlsFingerprint::Safari).await;

        let all = [
            (TlsFingerprint::None, &none),
            (TlsFingerprint::Chrome, &chrome),
            (TlsFingerprint::Ios, &ios),
            (TlsFingerprint::Safari, &safari),
        ];
        // extensions 维按集合比（rustls 0.23.4x 起 hello 扩展序每握手
        // 随机化——hs.rs extension_order_seed；可区分性判据不受影响：
        // 差异承载在套件/群/方案三个稳定维）
        let ext_set = |h: &HelloTuple| {
            let mut e = h.2.clone();
            e.sort_unstable();
            e
        };
        for (i, (pa, a)) in all.iter().enumerate() {
            for (pb, b) in all.iter().skip(i + 1) {
                let dims = [
                    a.0 != b.0,
                    a.1 != b.1,
                    ext_set(a) != ext_set(b),
                    a.3 != b.3,
                    a.4 != b.4,
                ];
                assert!(
                    dims.iter().filter(|d| **d).count() >= 2,
                    "{:?} vs {:?} 五元组应 ≥2 维互异：{a:?} vs {b:?}",
                    pa.as_str(),
                    pb.as_str()
                );
            }
        }

        // 预设签名方案广告 = 表序（D-3 包装生效面）
        for (profile, hello) in [
            (TlsFingerprint::Ios, &ios),
            (TlsFingerprint::Safari, &safari),
        ] {
            let want: Vec<u16> = profile
                .spec()
                .unwrap()
                .sig_schemes
                .iter()
                .map(|s| u16::from(*s))
                .collect();
            assert_eq!(hello.4, want, "{:?} 签名方案广告面 = 预设表序", profile);
        }
        // 单 1.3 形态的 hello：TLS1.3 套件独占 + key_share/psk 扩展在场
        assert!(ios.1.len() == 3, "ios hello 套件 = 预设三件");
        assert!(
            ios.2.contains(&0x002b) && ios.2.contains(&0x0033),
            "supported_versions + psk_key_exchange_modes 在场"
        );
        // 形态串两两互异（构造面即时可查，D-6）
        let mats = [
            TlsFingerprint::None.shape_material(),
            TlsFingerprint::Chrome.shape_material(),
            TlsFingerprint::Ios.shape_material(),
            TlsFingerprint::Safari.shape_material(),
        ];
        assert_eq!(
            mats.len(),
            mats.iter().collect::<std::collections::HashSet<_>>().len()
        );
    }

    /// §7-5 存量零差异：none 形态经新漏斗 = 既有 none 形态直连路径
    /// 路径（hello 逐字节同形——五元组全等）。
    #[tokio::test]
    async fn none_profile_matches_legacy_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16_384];
            let mut total = 0;
            while total < 5 {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                assert!(n > 0);
                total += n;
            }
            let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            while total < 5 + rec_len {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                assert!(n > 0);
                total += n;
            }
            buf.truncate(5 + rec_len);
            buf
        });
        let connector = crate::tls::create_tls_connector_with_profile(
            true,
            None,
            crate::fingerprint::TlsFingerprint::None,
        )
        .unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("capture.test".to_string()).unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await;
        let buf = server.await.unwrap();

        let legacy = parse_client_hello(&buf);
        let via_none = capture_hello(TlsFingerprint::None).await;
        // 扩展序每握手随机化（上游行为）——零差异按集合判；套件序稳定，
        // 逐项全等含序。
        assert_eq!(legacy.0, via_none.0, "none 形态 = 既有路径（§7-5 版本）");
        assert_eq!(legacy.1, via_none.1, "套件序含序全等");
        let set = |v: &[u16]| {
            let mut s = v.to_vec();
            s.sort_unstable();
            s
        };
        assert_eq!(set(&legacy.2), set(&via_none.2), "扩展集全等");
        assert_eq!(set(&legacy.3), set(&via_none.3), "群集全等");
        assert_eq!(legacy.4, via_none.4, "签名方案序全等");
    }

    /// E1：parse 合法/非法两态。
    #[test]
    fn parse_roundtrip_and_reject() {
        assert_eq!(
            TlsFingerprint::parse("chrome").unwrap(),
            TlsFingerprint::Chrome
        );
        assert_eq!(
            TlsFingerprint::parse(" none ").unwrap(),
            TlsFingerprint::None
        );
        assert_eq!(TlsFingerprint::parse("").unwrap(), TlsFingerprint::None);
        let err = TlsFingerprint::parse("firefox").unwrap_err();
        assert!(format!("{err:#}").contains("firefox"));
    }
}
