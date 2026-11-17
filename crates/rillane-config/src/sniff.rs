//! RIL-143 有界域名嗅探策略（纯面）。
//!
//! 口径（todo RIL-143「关闭/按需/范围」三态）：
//! - `off`：不做任何首包嗅探（零 peek，零首包时延）；
//! - `on_demand`（缺省）：仅当路由面缺域名（目标为 IP 字面量）时嗅探——
//!   既有 TUN 面目标恒为字面量，缺省 = 既有行为零差异；
//! - `scope`：仅对显式声明的目标端口嗅探——**覆盖目标需显式配置**
//!   （端口表空 = 不嗅探任何流）。
//!
//! 首包字节/时间双界可配且有硬上限（[`SNIFF_MAX_BYTES_CAP`] /
//! [`SNIFF_TIMEOUT_MS_CAP`]）：嗅探只 peek 首包明文（不消费数据，
//! forward 首包照常可读），绝不解密 HTTPS、不推断 PID、不越认证边界。
//! 嗅探命中以 `sniff.source`（`tls_sni` | `http_host`）+ `sniff.domain`
//! 注记交付来源契约；ECH（加密 ClientHello 无 server_name）与不支持
//! 版本（SSLv2 记录 / QUIC draft）返回未知（None），不猜测域名。

use serde::{Deserialize, Serialize};

/// 缺省首包字节界：单条最大 TLS 记录 16384 + 5 字节记录头
pub const SNIFF_DEFAULT_MAX_BYTES: u32 = 16389;
/// 首包字节界硬上限（IPv4 单包上限口径）
pub const SNIFF_MAX_BYTES_CAP: u32 = 65535;
/// 缺省首包等待（毫秒）
pub const SNIFF_DEFAULT_TIMEOUT_MS: u64 = 120;
/// 首包等待硬上限（毫秒）——嗅探引入的首包时延不得失控
pub const SNIFF_TIMEOUT_MS_CAP: u64 = 1000;

/// 嗅探模式（RIL-143 三态；serde 名 snake_case）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum SniffMode {
    /// 关闭：不做任何首包嗅探
    Off,
    /// 按需（缺省）：仅当目标为 IP 字面量（路由面缺域名）时嗅探
    #[default]
    OnDemand,
    /// 范围：仅对显式声明的目标端口嗅探（覆盖目标需显式配置）
    Scope,
}

/// 有界域名嗅探策略（RIL-143）：`network.sniff` 声明面。缺省 = 按需 +
/// 既有双界（16389B / 120ms）——块缺席或字段缺席均零差异。
/// deny_unknown_fields 让拼错子字段立刻报错。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SniffPolicy {
    /// 嗅探模式
    pub mode: SniffMode,
    /// scope 模式的显式覆盖端口表（off/on_demand 忽略；不拒绝）
    pub ports: Vec<u16>,
    /// 首包字节界（peek 上限；1..=65535）
    pub max_bytes: u32,
    /// 首包时间界（peek 等待毫秒；1..=1000）
    pub timeout_ms: u64,
}

impl Default for SniffPolicy {
    fn default() -> Self {
        Self {
            mode: SniffMode::OnDemand,
            ports: Vec::new(),
            max_bytes: SNIFF_DEFAULT_MAX_BYTES,
            timeout_ms: SNIFF_DEFAULT_TIMEOUT_MS,
        }
    }
}

impl SniffPolicy {
    /// 嗅探门（纯函数，RIL-143）：策略 × 流目标 → 是否对本流做首包
    /// 嗅探。`target_is_ip` = 目标主机是 IP 字面量（路由面缺域名证据）；
    /// `dst_port` = 流目标端口。
    pub fn applies(&self, target_is_ip: bool, dst_port: u16) -> bool {
        match self.mode {
            SniffMode::Off => false,
            SniffMode::OnDemand => target_is_ip,
            SniffMode::Scope => self.ports.contains(&dst_port),
        }
    }

    /// 构建期校验（RIL-143）：字节/时间双界（≥1 且不越硬上限——有界性
    /// 是验收面）；`scope` 的覆盖目标需显式配置（端口表非空）。`off`
    /// 忽略端口表（不拒绝——多余声明无害）。
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mode == SniffMode::Scope {
            anyhow::ensure!(
                !self.ports.is_empty(),
                "sniff.mode = scope 须显式声明覆盖端口（network.sniff.ports）——覆盖目标需显式配置"
            );
        }
        anyhow::ensure!(
            self.max_bytes >= 1 && self.max_bytes <= SNIFF_MAX_BYTES_CAP,
            "network.sniff.max_bytes 须在 1..={SNIFF_MAX_BYTES_CAP}（首包字节界），当前 {}",
            self.max_bytes
        );
        anyhow::ensure!(
            self.timeout_ms >= 1 && self.timeout_ms <= SNIFF_TIMEOUT_MS_CAP,
            "network.sniff.timeout_ms 须在 1..={SNIFF_TIMEOUT_MS_CAP}（首包时间界毫秒），当前 {}",
            self.timeout_ms
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 缺省 = 按需 + 既有双界（零差异口径钉住）
    #[test]
    fn default_is_on_demand_with_bounded_limits() {
        let p = SniffPolicy::default();
        assert_eq!(p.mode, SniffMode::OnDemand);
        assert_eq!(p.max_bytes, SNIFF_DEFAULT_MAX_BYTES);
        assert_eq!(p.timeout_ms, SNIFF_DEFAULT_TIMEOUT_MS);
        assert!(p.validate().is_ok());
    }

    /// 门矩阵：off 恒不嗅探；on_demand 只嗅 IP 字面量；scope 只认显式端口
    #[test]
    fn gate_matrix_by_mode() {
        let off = SniffPolicy {
            mode: SniffMode::Off,
            ports: vec![443],
            ..SniffPolicy::default()
        };
        assert!(!off.applies(true, 443), "off 恒不嗅探");
        assert!(off.validate().is_ok(), "off 忽略端口表");

        let on_demand = SniffPolicy::default();
        assert!(on_demand.applies(true, 443), "IP 字面量按需嗅探");
        assert!(
            !on_demand.applies(false, 443),
            "已有域名证据（域名目标）不重复嗅探"
        );

        let scope = SniffPolicy {
            mode: SniffMode::Scope,
            ports: vec![443, 8443],
            ..SniffPolicy::default()
        };
        assert!(scope.applies(true, 443));
        assert!(!scope.applies(true, 80), "未声明端口不嗅探");
        assert!(scope.applies(false, 443), "scope 只看端口表——不看 IP 面");
    }

    /// scope 端口表空 = 不嗅探任何流（不缺省回落全端口——覆盖目标需显式配置）
    #[test]
    fn scope_with_empty_ports_never_applies() {
        let scope = SniffPolicy {
            mode: SniffMode::Scope,
            ..SniffPolicy::default()
        };
        assert!(!scope.applies(true, 443));
        assert!(scope.validate().is_err(), "空端口表校验拒绝");
    }

    /// 校验点名：双界越界与 scope 空端口
    #[test]
    fn validate_names_each_refusal() {
        let p = SniffPolicy {
            mode: SniffMode::Scope,
            ..SniffPolicy::default()
        };
        let err = p.validate().expect_err("scope 空端口须拒绝");
        assert!(err.to_string().contains("ports"), "点名 ports: {err}");

        let p = SniffPolicy {
            max_bytes: 0,
            ..SniffPolicy::default()
        };
        let err = p.validate().expect_err("0 字节界须拒绝");
        assert!(
            err.to_string().contains("max_bytes"),
            "点名 max_bytes: {err}"
        );

        let p = SniffPolicy {
            max_bytes: SNIFF_MAX_BYTES_CAP + 1,
            ..SniffPolicy::default()
        };
        assert!(p.validate().is_err(), "越字节硬上限须拒绝");

        let p = SniffPolicy {
            timeout_ms: 0,
            ..SniffPolicy::default()
        };
        let err = p.validate().expect_err("0 时间界须拒绝");
        assert!(
            err.to_string().contains("timeout_ms"),
            "点名 timeout_ms: {err}"
        );

        let p = SniffPolicy {
            timeout_ms: SNIFF_TIMEOUT_MS_CAP + 1,
            ..SniffPolicy::default()
        };
        assert!(p.validate().is_err(), "越时间硬上限须拒绝");
    }

    /// serde：snake_case 模式名与块级缺省（字段缺席取 Default = 既有双界）
    #[test]
    fn serde_snake_case_and_block_defaults() {
        let p: SniffPolicy =
            serde_json::from_str(r#"{"mode":"scope","ports":[443]}"#).expect("可解析");
        assert_eq!(p.mode, SniffMode::Scope);
        assert_eq!(p.ports, vec![443]);
        assert_eq!(p.max_bytes, SNIFF_DEFAULT_MAX_BYTES, "字段缺席取缺省双界");
        let json = serde_json::to_string(&SniffPolicy::default()).expect("可序列化");
        assert!(
            json.contains("\"mode\":\"on_demand\""),
            "模式名 snake_case: {json}"
        );
    }
}
