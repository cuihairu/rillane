use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SeepConfig {
    pub control: ControlConfig,
    pub telemetry: TelemetryConfig,
    pub ingress: Vec<IngressDescriptor>,
    pub egress: Vec<EgressDescriptor>,
    pub routing: RoutingConfig,
}

impl SeepConfig {
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件: {}", path.display()))?;
        let hint = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);
        Self::from_str(&raw, hint.as_deref())
    }

    pub fn from_str(raw: &str, hint: Option<&str>) -> Result<Self> {
        match hint {
            Some("json") => serde_json::from_str(raw).context("JSON 配置解析失败"),
            Some("toml") => toml::from_str(raw).context("TOML 配置解析失败"),
            Some("yaml") | Some("yml") => serde_yaml::from_str(raw).context("YAML 配置解析失败"),
            _ => serde_yaml::from_str(raw)
                .or_else(|_| serde_json::from_str(raw))
                .or_else(|_| toml::from_str(raw))
                .context("无法识别配置格式"),
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        PathBuf::from("/etc/seep")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub api_bind: String,
    pub uds_path: Option<PathBuf>,
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: IngressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDescriptor {
    pub name: String,
    #[serde(flatten)]
    pub spec: EgressConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IngressConfig {
    Socks5 {
        bind: String,
        auth: Option<Vec<Credential>>,
    },
    Http {
        bind: String,
    },
    Mixed {
        bind: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressConfig {
    Direct,
    Trojan {
        server: String,
        port: u16,
        password: String,
    },
    Shadowsocks {
        server: String,
        port: u16,
        method: String,
        password: String,
    },
    Wireguard {
        endpoint: String,
        private_key: String,
        peer_public_key: String,
        address: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub default_node: String,
    pub groups: Vec<PolicyGroup>,
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    pub name: String,
    pub strategy: Strategy,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Fixed,
    Latency,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    pub matches: Vec<MatchCondition>,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    DomainSuffix { values: Vec<String> },
    DomainKeyword { values: Vec<String> },
    Geoip { country: String },
    Network { cidrs: Vec<String> },
    Port { values: Vec<u16> },
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("未知的入口类型: {0}")]
    UnknownIngress(String),
    #[error("未知的出口类型: {0}")]
    UnknownEgress(String),
}
