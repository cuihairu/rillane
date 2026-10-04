//! obfuscation 配置区块 → 混淆策略转换（obfuscation-middleware.md §3.2）
//!
//! 裁决同 `network_config`：seep-config 镜像 serde 类型，转换落本 crate
//! （`UdpConfig`/`NetworkBlockConfig` 先例）。M0 交付策略解析（profile 选择 +
//! spec 映射）；M1 本文件补链构造（`PaddingMiddleware` 消费 `PaddingPolicy`，
//! 选择器闭包固化，§8 分步）。

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use tracing::warn;

use seep_config::{
    ApplyTo, ObfuscationConfig, PaddingBlockConfig, ShapingBlockConfig, TimingBlockConfig,
};
use seep_core::{
    FlowMiddleware, MiddlewareChain, PaddingMode, PaddingSpec, ShapingMode, ShapingSpec,
    TimingMode, TimingSpec,
};
use seep_protocols::middleware::{
    LatencyProbe, PadSelector, PaddingMiddleware, ShapingMiddleware, ShapingSelector,
    TimingMiddleware, TimingSelector, ANN_OBFS_PADDING,
};

/// 解析后的 padding 策略（选择器 + spec）：M1 构建 middleware 链、M2
/// `PaddingMiddleware` 的构造输入。选择器按 §1.4 注解值匹配（`seep.route.kind`
/// = "chain"/"single"，`seep.route.egress` = 最终节点名，M1 注入）。
#[derive(Debug, Clone, PartialEq)]
pub struct PaddingPolicy {
    pub apply_to: ApplyTo,
    pub spec: PaddingSpec,
}

impl PaddingPolicy {
    /// 选择器匹配（§3.2 表行 2 的判定核心，注解值的字符串形）：
    /// `kind` = `seep.route.kind`，`egress` = `seep.route.egress`（None = 未注入）。
    pub fn matches(&self, kind: &str, egress: Option<&str>) -> bool {
        match &self.apply_to {
            ApplyTo::Chain => kind == "chain",
            ApplyTo::Single => kind == "single",
            ApplyTo::All => true,
            ApplyTo::Egress(name) => egress == Some(name.as_str()),
        }
    }
}

/// `ObfuscationConfig` → `PaddingPolicy`（§3.2 转换映射表）。
///
/// - `enabled=false` → `Ok(None)`：构建期零 middleware 零注解（§2.5 零开销旁路）；
/// - E5：`apply_to = egress:<name>` 且 name 不在 `known_egress` → warning +
///   降级不生效 → `Ok(None)`（不 Err：egress 名可来自订阅热更新，构建期未必齐备）；
/// - spec 映射：mode 字符串 → `PaddingMode`，字段按模式拷贝、非本模式字段
///   保持缺省（0/空，策略引擎按 mode 取用）。
pub fn to_padding_policy(
    cfg: &ObfuscationConfig,
    known_egress: &[&str],
) -> Result<Option<PaddingPolicy>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if let ApplyTo::Egress(name) = &cfg.apply_to {
        if !known_egress.contains(&name.as_str()) {
            warn!(
                target: "seep::obfs",
                egress = %name,
                "obfuscation.apply_to 指向不存在的 egress，降级为不生效（E5：egress 名可来自订阅热更新）"
            );
            return Ok(None);
        }
    }
    let block = match (&cfg.default_padding, &cfg.padding) {
        (Some(name), None) => cfg
            .profiles
            .get(name)
            .and_then(|profile| profile.padding.as_ref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "obfuscation.default_padding 指向未定义或无 padding 的 profile：{name:?}（E3/E1）"
                )
            })?,
        (None, Some(inline)) => inline,
        // validate（§3.3-2）已拦互斥/皆缺；此处防御未过 validate 的直调
        (Some(_), Some(_)) => anyhow::bail!("default_padding 与内联 padding 互斥（§3.3-2）"),
        // P2-4 调整：enabled 时 padding 维可缺（由 timing/shaping 维承载策略）——
        // 「 enabled 且三维皆缺」由 config validate E1 兜底；本函数维间语义对称（None = 未启用本维）
        (None, None) => return Ok(None),
    };
    let spec = padding_block_to_spec(block)?;
    Ok(Some(PaddingPolicy {
        apply_to: cfg.apply_to.clone(),
        spec,
    }))
}

/// `PaddingBlockConfig` → `PaddingSpec`（§3.2 表末行）：mode 字符串 → 枚举，
/// 非法 mode 带原值 Err（E2；validate 未前置时的直调防御）。
fn padding_block_to_spec(block: &PaddingBlockConfig) -> Result<PaddingSpec> {
    let mode = match block.mode.as_str() {
        "fixed" => PaddingMode::Fixed,
        "bucket" => PaddingMode::Bucket,
        "range" => PaddingMode::Range,
        other => {
            anyhow::bail!("obfuscation.padding.mode 非法：{other:?}（E2，须为 fixed|bucket|range）")
        }
    };
    Ok(PaddingSpec {
        mode,
        target: block.target,
        buckets: block.buckets.clone(),
        min: block.min,
        max: block.max,
        max_overhead_ratio: block.max_overhead_ratio,
    })
}

/// P2-4 §3：解析后的 timing 策略（选择器 + spec），与 `PaddingPolicy`
/// 对称。§7 选择器匹配同语义。
#[derive(Debug, Clone, PartialEq)]
pub struct TimingPolicy {
    pub apply_to: ApplyTo,
    pub spec: TimingSpec,
}

impl TimingPolicy {
    pub fn matches(&self, kind: &str, egress: Option<&str>) -> bool {
        match &self.apply_to {
            ApplyTo::Chain => kind == "chain",
            ApplyTo::Single => kind == "single",
            ApplyTo::All => true,
            ApplyTo::Egress(name) => egress == Some(name.as_str()),
        }
    }
}

/// P2-4 §3：解析后的 shaping 策略，与 `PaddingPolicy` 对称。
#[derive(Debug, Clone, PartialEq)]
pub struct ShapingPolicy {
    pub apply_to: ApplyTo,
    pub spec: ShapingSpec,
}

impl ShapingPolicy {
    pub fn matches(&self, kind: &str, egress: Option<&str>) -> bool {
        match &self.apply_to {
            ApplyTo::Chain => kind == "chain",
            ApplyTo::Single => kind == "single",
            ApplyTo::All => true,
            ApplyTo::Egress(name) => egress == Some(name.as_str()),
        }
    }
}

/// `ObfuscationConfig` → `TimingPolicy`（P2-4 §3 对称 to_padding_policy）：
/// 语义同——enabled 总开关短路、E5 降级、default_timing 与内联互斥（防御）、
/// profile 内嵌解析；至少一维策略是调用侧 validate 的责任，本函数两块皆 None
/// 时 → Ok(None)（timing 维未启用即不生 middleware）。
pub fn to_timing_policy(
    cfg: &ObfuscationConfig,
    known_egress: &[&str],
) -> Result<Option<TimingPolicy>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if let ApplyTo::Egress(name) = &cfg.apply_to {
        if !known_egress.contains(&name.as_str()) {
            warn!(
                target: "seep::obfs",
                egress = %name,
                "obfuscation.apply_to 指向不存在的 egress，降级为不生效（E5）"
            );
            return Ok(None);
        }
    }
    let block = match (&cfg.default_timing, &cfg.timing) {
        (Some(name), None) => cfg
            .profiles
            .get(name)
            .and_then(|profile| profile.timing.as_ref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "obfuscation.default_timing 指向未定义或无 timing 的 profile：{name:?}（E3/E1）"
                )
            })?,
        (None, Some(inline)) => inline,
        (Some(_), Some(_)) => anyhow::bail!("default_timing 与内联 timing 互斥（§3.3-2 同语义）"),
        (None, None) => return Ok(None),
    };
    let spec = timing_block_to_spec(block)?;
    Ok(Some(TimingPolicy {
        apply_to: cfg.apply_to.clone(),
        spec,
    }))
}

/// `ObfuscationConfig` → `ShapingPolicy`（P2-4 §3 对称 to_padding_policy）。
pub fn to_shaping_policy(
    cfg: &ObfuscationConfig,
    known_egress: &[&str],
) -> Result<Option<ShapingPolicy>> {
    if !cfg.enabled {
        return Ok(None);
    }
    if let ApplyTo::Egress(name) = &cfg.apply_to {
        if !known_egress.contains(&name.as_str()) {
            warn!(
                target: "seep::obfs",
                egress = %name,
                "obfuscation.apply_to 指向不存在的 egress，降级为不生效（E5）"
            );
            return Ok(None);
        }
    }
    let block = match (&cfg.default_shaping, &cfg.shaping) {
        (Some(name), None) => cfg
            .profiles
            .get(name)
            .and_then(|profile| profile.shaping.as_ref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "obfuscation.default_shaping 指向未定义或无 shaping 的 profile：{name:?}（E3/E1）"
                )
            })?,
        (None, Some(inline)) => inline,
        (Some(_), Some(_)) => {
            anyhow::bail!("default_shaping 与内联 shaping 互斥（§3.3-2 同语义）")
        }
        (None, None) => return Ok(None),
    };
    let spec = shaping_block_to_spec(block)?;
    Ok(Some(ShapingPolicy {
        apply_to: cfg.apply_to.clone(),
        spec,
    }))
}

/// `TimingBlockConfig` → `TimingSpec`：mode 字符串 → 枚举，非法 mode
/// 带原值 Err（E2；validate 未前置时的直调防御）。
fn timing_block_to_spec(block: &TimingBlockConfig) -> Result<TimingSpec> {
    let mode = match block.mode.as_str() {
        "fixed" => TimingMode::Fixed,
        "uniform" => TimingMode::Uniform,
        other => {
            anyhow::bail!("obfuscation.timing.mode 非法：{other:?}（E2，须为 fixed|uniform）")
        }
    };
    Ok(TimingSpec {
        mode,
        fixed_ms: block.fixed_ms,
        min_ms: block.min_ms,
        max_ms: block.max_ms,
        max_delay_ms: block.max_delay_ms,
    })
}

/// `ShapingBlockConfig` → `ShapingSpec`：同上。
fn shaping_block_to_spec(block: &ShapingBlockConfig) -> Result<ShapingSpec> {
    let mode = match block.mode.as_str() {
        "interval" => ShapingMode::Interval,
        other => {
            anyhow::bail!("obfuscation.shaping.mode 非法：{other:?}（E2，须为 interval）")
        }
    };
    Ok(ShapingSpec {
        mode,
        interval_ms: block.interval_ms,
        jitter_ms: block.jitter_ms,
        max_delay_ms: block.max_delay_ms,
    })
}

/// P1-4 §4.2/E9：从 `seep.obfs.padding` 注解提取 spec——注解缺失或非法
/// JSON 一律 `None`（不填充：伪装是增益，不得破坏转发）。帧执行侧
/// （`forward_chain` → `dial_and_tunnel`）的消费入口。
pub fn padding_spec_from_annotations(
    annotations: &BTreeMap<String, String>,
) -> Option<PaddingSpec> {
    annotations
        .get(ANN_OBFS_PADDING)
        .and_then(|json| serde_json::from_str(json).ok())
}

/// `ObfuscationConfig` → `MiddlewareChain`（§3.2 表行 1：MVP 至多一个
/// `PaddingMiddleware` + 调试显式挂的 `LatencyProbe`；§1.5 声明序即执行序）。
///
/// - 块缺席 / `enabled=false` → 空链（§2.5：build 期不构造任何 middleware，
///   `latency_probe` 亦不挂——关闭语义覆盖整块，E11）；
/// - `padding` → `to_padding_policy` 解析策略 + 选择器闭包固化（闭包捕获
///   `PaddingPolicy` 委托 `matches`，§3.2 表行 2；E5 降级 None 时不挂）；
/// - `latency_probe` → 显式挂载（§4.1：1ms sleep 为占位语义，默认不挂，
///   仅配置声明时用于验证管线连通与调试）；
/// - 未知名字 → Err（validate §3.3-5 已拦，此处直调防御）。
pub fn build_middleware_chain(
    cfg: Option<&ObfuscationConfig>,
    known_egress: &[&str],
) -> Result<MiddlewareChain> {
    let Some(cfg) = cfg else {
        return Ok(MiddlewareChain::default());
    };
    if !cfg.enabled {
        return Ok(MiddlewareChain::default());
    }
    let padding_policy = to_padding_policy(cfg, known_egress)?;
    let timing_policy = to_timing_policy(cfg, known_egress)?;
    let shaping_policy = to_shaping_policy(cfg, known_egress)?;
    let mut mws: Vec<Arc<dyn FlowMiddleware>> = Vec::new();
    for name in &cfg.middleware {
        match name.as_str() {
            "padding" => {
                if let Some(policy) = padding_policy.clone() {
                    let spec = policy.spec.clone();
                    let selector: PadSelector =
                        Box::new(move |kind, egress| policy.matches(kind, egress));
                    mws.push(Arc::new(PaddingMiddleware::new(spec, selector)));
                }
            }
            "latency_probe" => mws.push(Arc::new(LatencyProbe::new())),
            "timing" => {
                if let Some(policy) = timing_policy.clone() {
                    let spec = policy.spec.clone();
                    let selector: TimingSelector =
                        Box::new(move |kind, egress| policy.matches(kind, egress));
                    mws.push(Arc::new(TimingMiddleware::new(spec, selector)));
                }
            }
            "shaping" => {
                if let Some(policy) = shaping_policy.clone() {
                    let spec = policy.spec.clone();
                    let selector: ShapingSelector =
                        Box::new(move |kind, egress| policy.matches(kind, egress));
                    mws.push(Arc::new(ShapingMiddleware::new(spec, selector)));
                }
            }
            other => anyhow::bail!(
                "obfuscation.middleware 含未知名字 {other:?}（须为 padding|latency_probe|timing|shaping，§3.3-5）"
            ),
        }
    }
    // P3-2（plugin-loader.md §2.1/§2.3）：插件在内置链之后按声明序追加——
    // 链序 = 内置声明序 + plugins 声明序；JIT 编译在此同步发生（装配期，不占运行期）
    for plugin in &cfg.plugins {
        let opts = seep_plugins::PluginLoadOptions {
            fuel: plugin.fuel.unwrap_or(seep_plugins::DEFAULT_PLUGIN_FUEL),
        };
        let mw = seep_plugins::load_plugin(&plugin.path, opts)?;
        mws.push(mw);
    }
    Ok(MiddlewareChain::new(mws))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use seep_config::{ObfsPluginConfig, ObfsProfileConfig};
    use seep_core::{PaddingMode, PaddingSpec};

    use super::*;

    fn profile_cfg() -> ObfuscationConfig {
        ObfuscationConfig {
            default_timing: None,
            timing: None,
            default_shaping: None,
            shaping: None,
            enabled: true,
            default_padding: Some("game".to_string()),
            apply_to: ApplyTo::default(),
            middleware: vec!["padding".to_string()],
            profiles: BTreeMap::from([(
                "game".to_string(),
                ObfsProfileConfig {
                    timing: None,
                    shaping: None,
                    padding: Some(PaddingBlockConfig {
                        mode: "bucket".to_string(),
                        target: 0,
                        buckets: vec![256, 512, 1024],
                        min: 0,
                        max: 0,
                        max_overhead_ratio: 0.5,
                    }),
                },
            )]),
            padding: None,
            plugins: Vec::new(),
        }
    }

    /// P2-4 §7-2：to_timing_policy 矩阵——enabled 短路零触 / profile 引用解析 /
    /// 内联生效 + spec JSON 往返（注解形契约）/ E5 降级 None / 直调防御面
    /// （互斥 / E3 / E2 带原值）。
    #[test]
    fn to_timing_policy_matrix() {
        // 短路：disabled 时即便非法块也不触碰转换
        let mut cfg = profile_cfg();
        cfg.enabled = false;
        cfg.timing = Some(TimingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        });
        assert_eq!(to_timing_policy(&cfg, &[]).unwrap(), None);

        // None 维：未配 timing 即 Ok(None)（timing 维未启用）
        cfg.enabled = true;
        cfg.timing = None;
        assert_eq!(to_timing_policy(&cfg, &[]).unwrap(), None);

        // profile 引用解析
        let mut with_profile = profile_cfg();
        with_profile.default_timing = Some("game".to_string());
        with_profile.profiles.get_mut("game").unwrap().timing = Some(TimingBlockConfig {
            mode: "uniform".to_string(),
            min_ms: 5,
            max_ms: 30,
            max_delay_ms: 50,
            ..Default::default()
        });
        let policy = to_timing_policy(&with_profile, &[])
            .unwrap()
            .expect("profile timing 应解析");
        assert_eq!(policy.spec.mode, TimingMode::Uniform);
        assert_eq!(policy.spec.min_ms, 5);
        assert_eq!(policy.spec.max_delay_ms, 50);

        // 内联生效 + JSON 往返
        let mut inline = profile_cfg();
        inline.timing = Some(TimingBlockConfig {
            mode: "fixed".to_string(),
            fixed_ms: 12,
            max_delay_ms: 20,
            ..Default::default()
        });
        let policy = to_timing_policy(&inline, &[])
            .unwrap()
            .expect("内联 timing 应生效");
        assert_eq!(policy.spec.mode, TimingMode::Fixed);
        assert_eq!(policy.spec.fixed_ms, 12);
        let json = serde_json::to_string(&policy.spec).unwrap();
        let back: TimingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy.spec);

        // E5 降级：apply_to=egress:ghost 且未知 egress
        let mut ghost = profile_cfg();
        ghost.apply_to = ApplyTo::Egress("ghost".to_string());
        ghost.timing = Some(TimingBlockConfig::default());
        assert_eq!(to_timing_policy(&ghost, &["hk-1"]).unwrap(), None);
        let mut hit = profile_cfg();
        hit.apply_to = ApplyTo::Egress("hk-1".to_string());
        hit.timing = Some(TimingBlockConfig {
            mode: "fixed".to_string(),
            fixed_ms: 1,
            max_delay_ms: 5,
            ..Default::default()
        });
        assert!(to_timing_policy(&hit, &["hk-1"]).unwrap().is_some());

        // 直调防御面：互斥 / E3 / E2 带原值
        let mut both = profile_cfg();
        both.default_timing = Some("game".to_string());
        both.timing = Some(TimingBlockConfig::default());
        assert!(to_timing_policy(&both, &[])
            .unwrap_err()
            .to_string()
            .contains("互斥"));
        let mut bad_ref = profile_cfg();
        bad_ref.default_timing = Some("ghost".to_string());
        assert!(to_timing_policy(&bad_ref, &[])
            .unwrap_err()
            .to_string()
            .contains("E3"));
        let mut bad_mode = profile_cfg();
        bad_mode.timing = Some(TimingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        });
        assert!(to_timing_policy(&bad_mode, &[])
            .unwrap_err()
            .to_string()
            .contains("bogus"));
    }

    /// P2-4 §7-2：to_shaping_policy 矩阵同 to_timing_policy。
    #[test]
    fn to_shaping_policy_matrix() {
        let mut cfg = profile_cfg();
        cfg.enabled = false;
        cfg.shaping = Some(ShapingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        });
        assert_eq!(to_shaping_policy(&cfg, &[]).unwrap(), None);

        cfg.enabled = true;
        cfg.shaping = None;
        assert_eq!(to_shaping_policy(&cfg, &[]).unwrap(), None);

        let mut with_profile = profile_cfg();
        with_profile.default_shaping = Some("game".to_string());
        with_profile.profiles.get_mut("game").unwrap().shaping = Some(ShapingBlockConfig {
            mode: "interval".to_string(),
            interval_ms: 20,
            jitter_ms: 5,
            max_delay_ms: 40,
        });
        let policy = to_shaping_policy(&with_profile, &[])
            .unwrap()
            .expect("profile shaping 应解析");
        assert_eq!(policy.spec.mode, ShapingMode::Interval);
        assert_eq!(policy.spec.interval_ms, 20);
        assert_eq!(policy.spec.jitter_ms, 5);

        let json = serde_json::to_string(&policy.spec).unwrap();
        let back: ShapingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy.spec);

        let mut both = profile_cfg();
        both.default_shaping = Some("game".to_string());
        both.shaping = Some(ShapingBlockConfig::default());
        assert!(to_shaping_policy(&both, &[])
            .unwrap_err()
            .to_string()
            .contains("互斥"));
        let mut bad_mode = profile_cfg();
        bad_mode.shaping = Some(ShapingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        });
        assert!(to_shaping_policy(&bad_mode, &[])
            .unwrap_err()
            .to_string()
            .contains("bogus"));
    }

    /// §2.5/§3.3-1：enabled=false 短路——半成品配置（非法 mode）也不触碰转换。
    #[test]
    fn disabled_yields_none() {
        let mut cfg = profile_cfg();
        cfg.enabled = false;
        cfg.default_padding = None;
        cfg.padding = Some(PaddingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        });
        assert_eq!(to_padding_policy(&cfg, &[]).unwrap(), None);
    }

    /// §3.2 表行 3：default_padding 引用解析 → 被选中 profile 的 padding 块。
    #[test]
    fn profile_reference_resolves() {
        let policy = to_padding_policy(&profile_cfg(), &[])
            .unwrap()
            .expect("profile 引用应解析出策略");
        assert_eq!(
            policy.spec,
            PaddingSpec {
                mode: PaddingMode::Bucket,
                target: 0,
                buckets: vec![256, 512, 1024],
                min: 0,
                max: 0,
                max_overhead_ratio: 0.5,
            }
        );
        assert_eq!(policy.apply_to, ApplyTo::Chain, "apply_to 缺省 chain");
    }

    /// §3.1：内联 padding（无 default_padding）直接生效；spec JSON 往返
    /// 钉住注解序列化形（`seep.obfs.padding` 注解 = 该 JSON）。
    #[test]
    fn inline_padding_resolves_and_spec_roundtrips() {
        let mut cfg = profile_cfg();
        cfg.default_padding = None;
        cfg.profiles.clear();
        cfg.padding = Some(PaddingBlockConfig {
            mode: "fixed".to_string(),
            target: 512,
            max_overhead_ratio: 0.3,
            ..Default::default()
        });
        let policy = to_padding_policy(&cfg, &[])
            .unwrap()
            .expect("内联策略应生效");
        assert_eq!(policy.spec.mode, PaddingMode::Fixed);
        assert_eq!(policy.spec.target, 512);

        // 注解形 = JSON 序列化往返等价（§2.2 serde 契约）
        let json = serde_json::to_string(&policy.spec).unwrap();
        let reparsed: PaddingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed, policy.spec);
    }

    /// §7.1 选择器：apply_to 四值对注解集的匹配/不匹配两态。
    #[test]
    fn selector_matches_four_variants() {
        let policy = |apply_to: ApplyTo| PaddingPolicy {
            apply_to,
            spec: PaddingSpec {
                mode: PaddingMode::Fixed,
                target: 512,
                buckets: vec![],
                min: 0,
                max: 0,
                max_overhead_ratio: 0.5,
            },
        };
        assert!(policy(ApplyTo::Chain).matches("chain", Some("hk-1")));
        assert!(!policy(ApplyTo::Chain).matches("single", Some("hk-1")));
        assert!(policy(ApplyTo::Single).matches("single", None));
        assert!(!policy(ApplyTo::Single).matches("chain", None));
        assert!(policy(ApplyTo::All).matches("chain", Some("hk-1")));
        assert!(policy(ApplyTo::All).matches("single", None));
        assert!(policy(ApplyTo::Egress("hk-1".into())).matches("single", Some("hk-1")));
        assert!(!policy(ApplyTo::Egress("hk-1".into())).matches("single", Some("jp-1")));
        assert!(!policy(ApplyTo::Egress("hk-1".into())).matches("single", None));
    }

    /// §6 E5：apply_to 指向不存在 egress → warning + 降级不生效（Ok(None) 不 Err）；
    /// 指向存在 egress 名则正常解析。
    #[test]
    fn unknown_egress_degrades_to_none() {
        let mut cfg = profile_cfg();
        cfg.apply_to = ApplyTo::Egress("ghost".to_string());
        assert_eq!(to_padding_policy(&cfg, &["hk-1"]).unwrap(), None);

        cfg.apply_to = ApplyTo::Egress("hk-1".to_string());
        assert!(to_padding_policy(&cfg, &["hk-1"]).unwrap().is_some());
    }

    /// 直调防御面（validate 未前置时）：E3 profile 无 padding /
    /// 互斥 / E2 非法 mode 逐条 Err；皆缺 padding 维 → Ok(None)（P2-4 维间
    /// 对称语义；全三维皆缺由 validate E1 兜底）。
    #[test]
    fn defensive_bails_without_validate() {
        let mut cfg = profile_cfg();
        cfg.default_padding = None;
        assert_eq!(to_padding_policy(&cfg, &[]).unwrap(), None);

        let mut cfg = profile_cfg();
        cfg.profiles.get_mut("game").unwrap().padding = None;
        let err = to_padding_policy(&cfg, &[]).unwrap_err();
        assert!(err.to_string().contains("E3/E1"), "{err}");

        let mut cfg = profile_cfg();
        cfg.padding = Some(PaddingBlockConfig {
            mode: "fixed".to_string(),
            target: 512,
            ..Default::default()
        });
        let err = to_padding_policy(&cfg, &[]).unwrap_err();
        assert!(err.to_string().contains("互斥"), "{err}");

        let mut cfg = profile_cfg();
        cfg.default_padding = None;
        cfg.padding = Some(PaddingBlockConfig {
            mode: "fixedx".to_string(),
            target: 512,
            ..Default::default()
        });
        let err = to_padding_policy(&cfg, &[]).unwrap_err();
        assert!(err.to_string().contains("fixedx"), "{err}");
    }

    /// §3.2 表行 1/§2.5/E11：块缺席或 enabled=false → 空链——关闭语义覆盖
    /// 整块（latency_probe 亦不挂）。
    #[test]
    fn build_chain_disabled_or_absent_yields_empty() {
        assert!(build_middleware_chain(None, &[]).unwrap().is_empty());

        let mut cfg = profile_cfg();
        cfg.enabled = false;
        cfg.middleware = vec!["latency_probe".to_string()];
        assert!(build_middleware_chain(Some(&cfg), &[]).unwrap().is_empty());
    }

    /// §1.5/§3.2：声明序挂载（[latency_probe, padding] → len=2）；E5 降级
    /// （apply_to 指向不存在 egress）时 padding 不挂、其余照挂。
    #[test]
    fn build_chain_mounts_in_declaration_order_with_e5_skip() {
        let mut cfg = profile_cfg();
        cfg.middleware = vec!["latency_probe".to_string(), "padding".to_string()];
        let chain = build_middleware_chain(Some(&cfg), &[]).unwrap();
        assert_eq!(chain.len(), 2);

        let mut cfg = profile_cfg();
        cfg.apply_to = ApplyTo::Egress("ghost".to_string());
        cfg.middleware = vec!["latency_probe".to_string(), "padding".to_string()];
        let chain = build_middleware_chain(Some(&cfg), &[]).unwrap();
        assert_eq!(chain.len(), 1, "E5 降级：padding 不挂，latency_probe 照挂");
    }

    /// P2-4 M1：timing/shaping 名进白名单，四名字混排声明序挂载。
    #[test]
    fn build_chain_mounts_all_four_in_declaration_order() {
        let mut cfg = profile_cfg();
        cfg.timing = Some(TimingBlockConfig {
            mode: "fixed".to_string(),
            fixed_ms: 1,
            max_delay_ms: 1,
            ..Default::default()
        });
        cfg.shaping = Some(ShapingBlockConfig {
            mode: "interval".to_string(),
            interval_ms: 1,
            max_delay_ms: 1,
            ..Default::default()
        });
        cfg.middleware = vec![
            "shaping".to_string(),
            "padding".to_string(),
            "timing".to_string(),
            "latency_probe".to_string(),
        ];
        let chain = build_middleware_chain(Some(&cfg), &[]).unwrap();
        assert_eq!(chain.len(), 4);
        let names = format!("{:?}", chain);
        let pos = |name: &str| names.find(name).unwrap();
        assert!(
            pos("shaping") < pos("padding")
                && pos("padding") < pos("timing")
                && pos("timing") < pos("latency_probe"),
            "声明序即执行序：{names}"
        );
    }

    /// §3.3-5 直调防御：未知 middleware 名 Err（带原值）。
    #[test]
    fn build_chain_unknown_name_bails() {
        let mut cfg = profile_cfg();
        cfg.middleware = vec!["bogus".to_string()];
        let err = build_middleware_chain(Some(&cfg), &[]).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }

    /// §4.2/E9：`seep.obfs.padding` 注解提取 spec——缺失/非法 JSON → None
    /// （不填充：伪装是增益，不得破坏转发）；合法 JSON 还原 spec。
    #[test]
    fn padding_spec_annotation_extraction_e9() {
        let spec = PaddingSpec {
            mode: PaddingMode::Fixed,
            target: 512,
            buckets: vec![],
            min: 0,
            max: 0,
            max_overhead_ratio: 0.5,
        };

        // 注解缺席 → None（空链关闭态 / 未选中流）
        let mut ann = BTreeMap::new();
        assert_eq!(padding_spec_from_annotations(&ann), None);

        // 非法 JSON → None（E9：静默放弃填充，不 Err）
        ann.insert(ANN_OBFS_PADDING.to_string(), "not json".to_string());
        assert_eq!(padding_spec_from_annotations(&ann), None);

        // 合法 JSON（= PaddingMiddleware 写入形）→ 还原 spec
        ann.insert(
            ANN_OBFS_PADDING.to_string(),
            serde_json::to_string(&spec).unwrap(),
        );
        assert_eq!(padding_spec_from_annotations(&ann), Some(spec));
    }
    /// P3-2（plugin-loader.md §4.3）：build_middleware_chain 装配——plugins 在
    /// 内置链之后按声明序追加（链名序断言）、坏路径构建期 Err。
    #[test]
    fn build_chain_appends_plugins_after_builtins() {
        // 最小 wasm 插件（与 seep-plugins §4.1 同 ABI 面；wat 内联编译落盘）
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap (mut i32) (i32.const 1024))
            (data (i32.const 0) "chain-test-plugin\00")
            (func (export "alloc") (param $size i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $heap))
                (global.set $heap (i32.add (local.get $p) (i32.add (local.get $size) (i32.const 7))))
                (local.get $p))
            (func (export "plugin_name") (result i32) (i32.const 0))
            (func (export "on_flow") (param i32 i32 i32 i32) (result i32) (i32.const 0))
        )"#;
        let dir = std::env::temp_dir().join(format!("seep-chain-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wasm_path = dir.join("chain-test.wasm");
        std::fs::write(&wasm_path, wat::parse_str(wat).unwrap()).unwrap();

        let mut cfg = profile_cfg();
        cfg.plugins = vec![ObfsPluginConfig {
            path: wasm_path.clone(),
            fuel: None,
        }];
        let chain = build_middleware_chain(Some(&cfg), &[]).expect("装配应成功");
        assert_eq!(chain.len(), 2, "内置 1 + 插件 1");
        // 链名序断言（MiddlewareChain Debug 以名字呈现）：padding 在前、插件在后
        let dbg = format!("{chain:?}");
        let pad = dbg.find("padding").expect("内置名应可见");
        let plug = dbg.find("chain-test-plugin").expect("插件名应可见");
        assert!(pad < plug, "插件应追加在内置链之后：{dbg}");

        // 坏路径构建期 Err（validate 拦存在性；此处钉直调防御面）
        cfg.plugins = vec![ObfsPluginConfig {
            path: dir.join("ghost.wasm"),
            fuel: None,
        }];
        let err = build_middleware_chain(Some(&cfg), &[]).unwrap_err();
        assert!(err.to_string().contains("ghost.wasm"), "{err:#}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
