//! 配置/能力契约（RIL-001）：规范 IR 的版本字段、构建/平台能力集与稳定
//! 原因码。旧配置缺 version 字段按 V1 适配；未知版本与不支持组合在解析/
//! 校验期产生稳定原因码（`config.version.unknown` /
//! `config.combo.unsupported`），不猜语义、不静默降级、不伪装成功。
//!
//! 内核（rillane-core）不依赖本 crate 与 Clash 格式——Clash/Mihomo 订阅
//! 只在 rillane-subscription 侧解析并收敛为本规范 IR。

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::RillaneConfig;

/// 稳定原因码：未知配置版本。
pub const CODE_UNKNOWN_VERSION: &str = "config.version.unknown";
/// 稳定原因码：当前能力集不支持的配置组合。
pub const CODE_UNSUPPORTED_COMBINATION: &str = "config.combo.unsupported";
/// 稳定原因码：未知的入口类型。
pub const CODE_UNKNOWN_INGRESS: &str = "config.ingress.unknown";
/// 稳定原因码：未知的出口类型。
pub const CODE_UNKNOWN_EGRESS: &str = "config.egress.unknown";

/// 配置契约稳定原因码（RIL-001 验收）：文案可演进，`code()` 恒定——
/// 调用方按码分支/上报，不按中文文案匹配。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// 未知配置版本
    #[error("{CODE_UNKNOWN_VERSION}: 配置版本 {version:?} 不被支持（当前支持: 1）")]
    UnknownVersion {
        /// 收到的版本字面量（原样报告，便于定位配置）
        version: String,
    },
    /// 当前能力集不支持该配置组合
    #[error("{CODE_UNSUPPORTED_COMBINATION}: 特性 {feature} 需要的能力未启用: {detail}")]
    UnsupportedCombination {
        /// 特性定位（配置块/字段路径，如 `network.dns`）
        feature: &'static str,
        /// 人读细节
        detail: String,
    },
    /// 未知的入口类型
    #[error("{CODE_UNKNOWN_INGRESS}: 未知的入口类型: {0}")]
    UnknownIngress(String),
    /// 未知的出口类型
    #[error("{CODE_UNKNOWN_EGRESS}: 未知的出口类型: {0}")]
    UnknownEgress(String),
}

impl ConfigError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ConfigError::UnknownVersion { .. } => CODE_UNKNOWN_VERSION,
            ConfigError::UnsupportedCombination { .. } => CODE_UNSUPPORTED_COMBINATION,
            ConfigError::UnknownIngress(_) => CODE_UNKNOWN_INGRESS,
            ConfigError::UnknownEgress(_) => CODE_UNKNOWN_EGRESS,
        }
    }
}

/// 规范配置版本（RIL-001）。当前唯一已定义版本：V1。旧配置缺 version
/// 字段经 `#[serde(default)]` 适配为 V1；显式未知版本在解析期拒绝并
/// 携带稳定原因码 `config.version.unknown`（文案见 `ConfigError`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConfigVersion {
    /// 版本 1（当前）
    #[default]
    V1,
}

impl ConfigVersion {
    /// 版本字符串（序列化口径）
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigVersion::V1 => "1",
        }
    }

    /// 从版本字面量解析；未知值返回稳定原因码文案（供 serde 与调用方共用）
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "1" | "1.0" | "1.1" => Ok(ConfigVersion::V1),
            other => Err(format!(
                "{CODE_UNKNOWN_VERSION}: 配置版本 {other:?} 不被支持（当前支持: 1）"
            )),
        }
    }
}

impl fmt::Display for ConfigVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ConfigVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConfigVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VersionVisitor;

        impl serde::de::Visitor<'_> for VersionVisitor {
            type Value = ConfigVersion;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "配置版本（字符串 \"1\" 或整数 1）")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<ConfigVersion, E> {
                ConfigVersion::parse(s).map_err(E::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<ConfigVersion, E> {
                if n == 1 {
                    Ok(ConfigVersion::V1)
                } else {
                    Err(E::custom(ConfigVersion::parse(&n.to_string()).unwrap_err()))
                }
            }
        }

        deserializer.deserialize_any(VersionVisitor)
    }
}

/// 构建/平台能力集（RIL-001）：运行环境如实声明拥有的能力；配置侧据此
/// 校验「不支持组合」→ 稳定原因码 `config.combo.unsupported`，而不是
/// 拨号期才炸或静默降级。能力位与现有配置块一一对应；尚未落到规范 IR
/// 配置面的位（如 `process_attribution`）由平台端口契约（RIL-004/005）
/// 继续接入，当前仅作为能力声明存在。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    /// UDP 数据面（`udp.enabled` 需要）
    pub udp_forwarding: bool,
    /// TUN/网络虚拟化接管（`network` 块需要）
    pub tun_ingress: bool,
    /// DNS 分流（`network.dns` 块需要）
    pub dns_partition: bool,
    /// 流量混淆（`obfuscation` 块需要）
    pub obfuscation: bool,
    /// 出站连接池（`egress_pool` 块需要）
    pub egress_pool: bool,
    /// 本机进程归因（RIL-004/005 接入；规范 IR 当前无进程条件）
    pub process_attribution: bool,
}

impl CapabilitySet {
    /// 全能力集（桌面 full 构建）
    pub fn full() -> Self {
        Self {
            udp_forwarding: true,
            tun_ingress: true,
            dns_partition: true,
            obfuscation: true,
            egress_pool: true,
            process_attribution: true,
        }
    }

    /// 最小能力集（small 构建：无 TUN/DNS 分流/混淆/连接池；UDP 保留）
    pub fn minimal() -> Self {
        Self {
            udp_forwarding: true,
            tun_ingress: false,
            dns_partition: false,
            obfuscation: false,
            egress_pool: false,
            process_attribution: false,
        }
    }

    /// 检查配置组合是否落在能力集内。超界即拒绝并点名特性（配置块/字段
    /// 路径），产生稳定原因码 `config.combo.unsupported`（RIL-001 验收）。
    pub fn validate_config(&self, config: &RillaneConfig) -> Result<(), ConfigError> {
        if config.udp.enabled && !self.udp_forwarding {
            return Err(ConfigError::UnsupportedCombination {
                feature: "udp.enabled",
                detail: "当前构建无 UDP 数据面".to_string(),
            });
        }

        if config.network.is_some() && !self.tun_ingress {
            return Err(ConfigError::UnsupportedCombination {
                feature: "network",
                detail: "当前构建无 TUN/网络虚拟化接管".to_string(),
            });
        }

        if let Some(network) = &config.network {
            if network.dns.is_some() && !self.dns_partition {
                return Err(ConfigError::UnsupportedCombination {
                    feature: "network.dns",
                    detail: "当前构建无 DNS 分流".to_string(),
                });
            }
        }

        if config.obfuscation.is_some() && !self.obfuscation {
            return Err(ConfigError::UnsupportedCombination {
                feature: "obfuscation",
                detail: "当前构建无混淆 middleware".to_string(),
            });
        }

        if config.egress_pool.is_some() && !self.egress_pool {
            return Err(ConfigError::UnsupportedCombination {
                feature: "egress_pool",
                detail: "当前构建无出站连接池".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for CapabilitySet {
    /// 缺省 = 全能力集：既有调用方不显式声明能力时行为不变（零差异）。
    fn default() -> Self {
        CapabilitySet::full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse_accepts_v1_spellings() {
        assert_eq!(ConfigVersion::parse("1"), Ok(ConfigVersion::V1));
        assert_eq!(ConfigVersion::parse("1.0"), Ok(ConfigVersion::V1));
        assert_eq!(ConfigVersion::parse("1.1"), Ok(ConfigVersion::V1));
        assert_eq!(ConfigVersion::parse(" 1 "), Ok(ConfigVersion::V1));
    }

    #[test]
    fn version_parse_rejects_unknown_with_stable_code() {
        let err = ConfigVersion::parse("2.0").unwrap_err();
        assert!(err.starts_with(CODE_UNKNOWN_VERSION), "实际: {err}");
        assert_eq!(
            ConfigError::UnknownVersion {
                version: "2.0".to_string()
            }
            .code(),
            CODE_UNKNOWN_VERSION
        );
    }

    #[test]
    fn capability_default_is_full() {
        assert_eq!(CapabilitySet::default(), CapabilitySet::full());
        assert_ne!(CapabilitySet::minimal(), CapabilitySet::full());
    }
}
