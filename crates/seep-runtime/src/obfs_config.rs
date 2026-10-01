//! obfuscation 配置区块 → 混淆策略转换（obfuscation-middleware.md §3.2）
//!
//! 裁决同 `network_config`：seep-config 镜像 serde 类型，转换落本 crate
//! （`UdpConfig`/`NetworkBlockConfig` 先例）。M0 交付策略解析（profile 选择 +
//! spec 映射）；middleware 链构造与选择器闭包固化归 M1/M2（`PaddingMiddleware`
//! 消费 `PaddingPolicy`，§8 分步）。

use anyhow::Result;
use tracing::warn;

use seep_config::{ApplyTo, ObfuscationConfig, PaddingBlockConfig};
use seep_core::{PaddingMode, PaddingSpec};

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
        (None, None) => anyhow::bail!("enabled=true 但未配策略（E1）"),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use seep_config::ObfsProfileConfig;
    use seep_core::{PaddingMode, PaddingSpec};

    use super::*;

    fn profile_cfg() -> ObfuscationConfig {
        ObfuscationConfig {
            enabled: true,
            default_padding: Some("game".to_string()),
            apply_to: ApplyTo::default(),
            middleware: vec!["padding".to_string()],
            profiles: BTreeMap::from([(
                "game".to_string(),
                ObfsProfileConfig {
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
        }
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

    /// 直调防御面（validate 未前置时）：E1 皆缺 / E1 profile 无 padding /
    /// 互斥 / E2 非法 mode 逐条 Err。
    #[test]
    fn defensive_bails_without_validate() {
        let mut cfg = profile_cfg();
        cfg.default_padding = None;
        let err = to_padding_policy(&cfg, &[]).unwrap_err();
        assert!(err.to_string().contains("E1"), "{err}");

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
}
