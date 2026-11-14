//! P1-4 obfuscation-middleware.md §7.1（M0 schema 半边）：obfuscation 块——
//! 存量零差异 / 缺省值 / deny 收口 / 往返 / validate 六规则 / apply_to 解析。
//! 转换半边见 rillane-runtime `obfs_config.rs`。

use std::collections::BTreeMap;

use rillane_config::{
    ApplyTo, ObfsPluginConfig, ObfsProfileConfig, ObfuscationConfig, PaddingBlockConfig,
    RillaneConfig,
};

const BASE_YAML: &str = r#"
control:
  api_bind: 127.0.0.1:9090
telemetry:
  log_level: info
  enable_metrics: true
  enable_tracing: false
ingress: []
egress: []
routing:
  default_node: direct
  groups: []
  rules: []
"#;

/// §3.4：存量配置无 obfuscation: → None，行为零差异；含块可解析且缺省值正确。
#[test]
fn obfuscation_block_defaults_backward_compatible() {
    let cfg: RillaneConfig = serde_yaml::from_str(BASE_YAML).expect("无 obfuscation 块应可解析");
    assert_eq!(cfg.obfuscation, None, "存量配置 obfuscation 应为 None");

    // §3.1 最小可用形态：内联 fixed 策略
    let yaml = format!(
        "{BASE_YAML}obfuscation:\n  enabled: true\n  padding:\n    mode: fixed\n    target: 512\n"
    );
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).expect("含 obfuscation 块应可解析");
    let obfs = cfg.obfuscation.expect("obfuscation 块应存在");
    assert!(obfs.enabled);
    assert_eq!(obfs.default_padding, None);
    assert_eq!(
        obfs.apply_to,
        ApplyTo::Chain,
        "apply_to 缺省 chain（§2.3 MVP 帧）"
    );
    assert_eq!(
        obfs.middleware,
        ["padding".to_string()],
        "middleware 缺省 [padding]"
    );
    assert!(obfs.profiles.is_empty());
    let inline = obfs.padding.expect("内联 padding 应存在");
    assert_eq!(inline.mode, "fixed");
    assert_eq!(inline.target, 512);
    assert_eq!(inline.max_overhead_ratio, 0.5, "ratio 缺省 0.5（§2.6）");
    assert!(inline.buckets.is_empty() && inline.min == 0 && inline.max == 0);

    // 关闭态（enabled 缺省 false）：半配置也应可解析（§3.3-1 容忍）
    let yaml = format!("{BASE_YAML}obfuscation:\n  padding:\n    mode: bogus\n");
    let cfg: RillaneConfig = serde_yaml::from_str(&yaml).expect("关闭态半配置应可解析");
    assert!(!cfg.obfuscation.unwrap().enabled);
}

/// §3.4：块级 deny_unknown_fields——三层拼错子字段构建期即报。
#[test]
fn obfuscation_block_denies_unknown_fields() {
    let yaml = "enabled: false\nunknwon: 1\n";
    let err = serde_yaml::from_str::<ObfuscationConfig>(yaml)
        .expect_err("obfuscation 未知字段应被 deny 拒绝");
    assert!(err.to_string().contains("unknown field"), "{err}");

    let yaml = "enabled: false\nprofiles:\n  game:\n    pading: {}\n";
    let err =
        serde_yaml::from_str::<ObfuscationConfig>(yaml).expect_err("profile 未知字段应被拒绝");
    assert!(err.to_string().contains("unknown field"), "{err}");

    let yaml = "enabled: false\npadding:\n  mode: fixed\n  targe: 512\n";
    let err =
        serde_yaml::from_str::<ObfuscationConfig>(yaml).expect_err("padding 未知字段应被拒绝");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

/// 含块配置 serde 往返等价（profiles 顺序稳定 + egress 选择器扁平字符串形）。
#[test]
fn obfuscation_block_serde_roundtrip() {
    let cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        default_padding: Some("game".to_string()),
        apply_to: ApplyTo::Egress("hk-1".to_string()),
        middleware: vec!["padding".to_string()],
        profiles: BTreeMap::from([
            (
                "game".to_string(),
                ObfsProfileConfig {
                    timing: None,
                    shaping: None,
                    padding: Some(PaddingBlockConfig {
                        mode: "bucket".to_string(),
                        buckets: vec![256, 512, 1024],
                        max_overhead_ratio: 0.5,
                        ..Default::default()
                    }),
                },
            ),
            (
                "web".to_string(),
                ObfsProfileConfig {
                    timing: None,
                    shaping: None,
                    padding: Some(PaddingBlockConfig {
                        mode: "range".to_string(),
                        min: 512,
                        max: 1400,
                        max_overhead_ratio: 0.3,
                        ..Default::default()
                    }),
                },
            ),
        ]),
        padding: None,
        plugins: Vec::new(),
    };
    let rendered = serde_yaml::to_string(&cfg).expect("应可序列化");
    assert!(
        rendered.contains("egress:hk-1"),
        "apply_to 应呈扁平字符串形：{rendered}"
    );
    let reparsed: ObfuscationConfig = serde_yaml::from_str(&rendered).expect("序列化结果应可往返");
    assert_eq!(reparsed, cfg);
}

/// §3.3 六规则矩阵（E1 互斥/皆缺、E3 策略名、E2 模式参数、middleware 白名单、
/// 关闭容忍），合法边界通过。
#[test]
fn obfuscation_validate_matrix() {
    let inline = || PaddingBlockConfig {
        mode: "fixed".to_string(),
        target: 512,
        ..Default::default()
    };

    // §3.3-1：关闭容忍半成品（非法 mode、无策略、未知 middleware 均不报）
    ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: false,
        padding: Some(PaddingBlockConfig {
            mode: "bogus".to_string(),
            ..Default::default()
        }),
        middleware: vec!["timing".to_string()],
        ..Default::default()
    }
    .validate()
    .expect("关闭态应容忍半配置");

    // §3.3-2：互斥
    let mut cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        default_padding: Some("game".to_string()),
        ..Default::default()
    };
    cfg.profiles.insert(
        "game".to_string(),
        ObfsProfileConfig {
            timing: None,
            shaping: None,
            padding: Some(inline()),
        },
    );
    cfg.padding = Some(inline());
    let err = cfg.validate().expect_err("并存应报互斥");
    assert!(err.to_string().contains("互斥"), "{err}");

    // §3.3-2：皆缺 = E1
    let mut cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        ..Default::default()
    };
    cfg.default_padding = None;
    cfg.padding = None;
    let err = cfg.validate().expect_err("皆缺应报 E1");
    assert!(err.to_string().contains("E1"), "{err}");

    // §3.3-3：策略名不存在 = E3；profile 无 padding = E1
    let mut cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        default_padding: Some("ghost".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().expect_err("未知策略名应报 E3");
    assert!(err.to_string().contains("E3"), "{err}");
    cfg.default_padding = Some("empty".to_string());
    cfg.profiles.insert(
        "empty".to_string(),
        ObfsProfileConfig {
            padding: None,
            timing: None,
            shaping: None,
        },
    );
    let err = cfg.validate().expect_err("无 padding profile 应报 E1");
    assert!(err.to_string().contains("E1"), "{err}");

    // §3.3-5：middleware 白名单（padding/latency_probe 合法，其余 Err）
    let mut cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        middleware: vec!["padding".to_string(), "latency_probe".to_string()],
        padding: Some(inline()),
        ..Default::default()
    };
    cfg.validate()
        .expect("padding + latency_probe 应通过（§4.1）");
    cfg.middleware = vec!["timing".to_string()];
    cfg.validate().expect("timing 白名单成员（P2-4 M1）应通过");
    cfg.middleware = vec!["shaping".to_string()];
    cfg.validate().expect("shaping 白名单成员（P2-4 M1）应通过");
    cfg.middleware = vec!["bogus_mw".to_string()];
    let err = cfg.validate().expect_err("未知 middleware 应报错");
    assert!(err.to_string().contains("bogus_mw"), "{err}");

    // §3.3-4：padding 块 E2 矩阵
    for (block, expect) in [
        (
            PaddingBlockConfig {
                mode: "fixedx".to_string(),
                target: 512,
                ..Default::default()
            },
            "mode",
        ),
        (
            PaddingBlockConfig {
                mode: "fixed".to_string(),
                target: 0,
                ..Default::default()
            },
            "target",
        ),
        (
            PaddingBlockConfig {
                mode: "bucket".to_string(),
                buckets: vec![],
                ..Default::default()
            },
            "buckets 非空",
        ),
        (
            PaddingBlockConfig {
                mode: "bucket".to_string(),
                buckets: vec![512, 256],
                ..Default::default()
            },
            "严格升序",
        ),
        (
            PaddingBlockConfig {
                mode: "range".to_string(),
                min: 1400,
                max: 512,
                ..Default::default()
            },
            "min ≤ max",
        ),
        (
            PaddingBlockConfig {
                mode: "fixed".to_string(),
                target: 512,
                max_overhead_ratio: -0.1,
                ..Default::default()
            },
            "≥ 0",
        ),
    ] {
        let err = block.validate().unwrap_err();
        assert!(err.to_string().contains(expect), "应报 {expect}：{err}");
    }

    // 合法边界：三模式 + 未选中的坏 profile 也被拦（validate 全量校验）
    PaddingBlockConfig {
        mode: "range".to_string(),
        min: 0,
        max: 0,
        ..Default::default()
    }
    .validate()
    .expect("range min=max=0 合法");
    let mut cfg = ObfuscationConfig {
        default_timing: None,
        timing: None,
        default_shaping: None,
        shaping: None,
        enabled: true,
        padding: Some(inline()),
        ..Default::default()
    };
    cfg.profiles.insert(
        "broken".to_string(),
        ObfsProfileConfig {
            timing: None,
            shaping: None,
            padding: Some(PaddingBlockConfig {
                mode: "bucket".to_string(),
                buckets: vec![],
                ..Default::default()
            }),
        },
    );
    let err = cfg
        .validate()
        .expect_err("未选中的坏 profile 也应构建期拦截");
    assert!(
        err.to_string().contains("broken"),
        "报错应点名 profile：{err}"
    );
}

/// §3.1：apply_to 扁平字符串形四值解析 + 未知值/空 egress 名报错 + YAML 直入。
#[test]
fn apply_to_parsing() {
    assert_eq!(ApplyTo::parse_config_str("chain").unwrap(), ApplyTo::Chain);
    assert_eq!(
        ApplyTo::parse_config_str("single").unwrap(),
        ApplyTo::Single
    );
    assert_eq!(ApplyTo::parse_config_str("all").unwrap(), ApplyTo::All);
    assert_eq!(
        ApplyTo::parse_config_str("egress:hk-1").unwrap(),
        ApplyTo::Egress("hk-1".to_string())
    );
    for bad in ["chainx", "", "egress:"] {
        assert!(ApplyTo::parse_config_str(bad).is_err(), "{bad:?} 应报错");
    }
    assert_eq!(ApplyTo::Chain.as_config_str(), "chain");
    assert_eq!(
        ApplyTo::Egress("hk-1".to_string()).as_config_str(),
        "egress:hk-1"
    );

    // YAML 入口：yaml 值不经引号也应解析（标量字符串）
    let yaml = "enabled: true\napply_to: egress:my-node\npadding:\n  mode: fixed\n  target: 512\n";
    let cfg: ObfuscationConfig = serde_yaml::from_str(yaml).expect("egress 选择器应可解析");
    assert_eq!(cfg.apply_to, ApplyTo::Egress("my-node".to_string()));

    let yaml = "enabled: true\napply_to: bogus\npadding:\n  mode: fixed\n  target: 512\n";
    let err =
        serde_yaml::from_str::<ObfuscationConfig>(yaml).expect_err("未知 apply_to 应解析报错");
    assert!(err.to_string().contains("bogus"), "{err}");
}

/// P2-4 §6-E2：timing/shaping 块解析 + validate 矩阵。
#[test]
fn timing_shaping_blocks_validate_matrix() {
    let yaml = r#"
enabled: true
default_timing: game
default_shaping: game
profiles:
  game:
    timing:
      mode: uniform
      min_ms: 5
      max_ms: 30
      max_delay_ms: 50
    shaping:
      mode: interval
      interval_ms: 20
      jitter_ms: 5
      max_delay_ms: 40
"#;
    let cfg: ObfuscationConfig = serde_yaml::from_str(yaml).expect("应解析");
    cfg.validate().expect("合法矩阵应过");

    // E2 矩阵
    let bad = |timing: Option<&str>, shaping: Option<&str>| {
        let mut y = String::from("enabled: true\n");
        if let Some(t) = timing {
            y.push_str(&format!("timing:\n{t}\n"));
        }
        if let Some(s) = shaping {
            y.push_str(&format!("shaping:\n{s}\n"));
        }
        let cfg: ObfuscationConfig = serde_yaml::from_str(&y).unwrap();
        cfg.validate()
    };
    // timing：非法 mode / fixed_ms=0 / uniform min>max / max_ms 破闸门
    assert!(bad(Some("  mode: bogus\n"), None)
        .unwrap_err()
        .to_string()
        .contains("E2"));
    assert!(bad(Some("  mode: fixed\n  max_delay_ms: 10\n"), None)
        .unwrap_err()
        .to_string()
        .contains("E2"));
    assert!(bad(
        Some("  mode: uniform\n  min_ms: 30\n  max_ms: 5\n  max_delay_ms: 50\n"),
        None
    )
    .unwrap_err()
    .to_string()
    .contains("E2"));
    assert!(bad(
        Some("  mode: uniform\n  min_ms: 0\n  max_ms: 60\n  max_delay_ms: 50\n"),
        None
    )
    .unwrap_err()
    .to_string()
    .contains("E2"));
    // shaping：非法 mode / interval 0 / jitter > interval / max_delay < interval
    assert!(bad(None, Some("  mode: bogus\n"))
        .unwrap_err()
        .to_string()
        .contains("E2"));
    assert!(bad(
        None,
        Some("  mode: interval\n  interval_ms: 0\n  max_delay_ms: 10\n")
    )
    .unwrap_err()
    .to_string()
    .contains("E2"));
    assert!(bad(
        None,
        Some("  mode: interval\n  interval_ms: 20\n  jitter_ms: 30\n  max_delay_ms: 40\n")
    )
    .unwrap_err()
    .to_string()
    .contains("E2"));
    assert!(bad(
        None,
        Some("  mode: interval\n  interval_ms: 20\n  max_delay_ms: 10\n")
    )
    .unwrap_err()
    .to_string()
    .contains("E2"));

    // 互斥：default_timing + 内联 timing
    let cfg: ObfuscationConfig = serde_yaml::from_str(
        "enabled: true\ndefault_timing: g\nprofiles:\n  g:\n    timing:\n      mode: fixed\n      fixed_ms: 1\n      max_delay_ms: 1\ntiming:\n  mode: fixed\n  fixed_ms: 1\n  max_delay_ms: 1\n",
    )
    .unwrap();
    assert!(cfg.validate().unwrap_err().to_string().contains("互斥"));

    // E1 扩展面：仅 timing 即可单独成策略
    let cfg: ObfuscationConfig = serde_yaml::from_str(
        "enabled: true\ntiming:\n  mode: fixed\n  fixed_ms: 1\n  max_delay_ms: 1\n",
    )
    .unwrap();
    cfg.validate().expect("仅 timing 也视为有策略");
}

/// P3-2（plugin-loader.md §4.3）：plugins 块校验矩阵——仅 plugins 亦满足 E1、
/// 路径不存在构建期拦截、关闭态容忍半成品（§3.3-1 同语义）、fuel ≥ 1、
/// deny_unknown_fields 收口。
#[test]
fn obfuscation_plugins_validate_matrix() {
    // validate 只查存在性，内容归载入器（rillane-plugins）
    let wasm = std::env::temp_dir().join(format!(
        "rillane-plugins-validate-{}.wasm",
        std::process::id()
    ));
    std::fs::write(&wasm, b"\0asm stub").unwrap();
    let plugin = |path: &std::path::Path, fuel: Option<u64>| ObfsPluginConfig {
        path: path.to_path_buf(),
        fuel,
    };

    // 仅 plugins（无内置策略）满足 E1（validate 扩 || !plugins.is_empty()）
    ObfuscationConfig {
        enabled: true,
        middleware: vec![],
        plugins: vec![plugin(&wasm, None)],
        ..Default::default()
    }
    .validate()
    .expect("plugins 应计入已配策略");

    // enabled + 路径不存在 → E1 构建期拦截
    let ghost = std::path::Path::new("/nonexistent/rillane/ghost.wasm");
    let err = ObfuscationConfig {
        enabled: true,
        middleware: vec![],
        plugins: vec![plugin(ghost, None)],
        ..Default::default()
    }
    .validate()
    .expect_err("路径不存在应报 E1");
    assert!(err.to_string().contains("E1"), "{err}");

    // 关闭态容忍半成品（路径不存在的条目不报）
    ObfuscationConfig {
        enabled: false,
        middleware: vec![],
        plugins: vec![plugin(ghost, None)],
        ..Default::default()
    }
    .validate()
    .expect("关闭态应容忍半成品配置");

    // fuel=0 拦截（指令预算下界）
    let err = ObfuscationConfig {
        enabled: true,
        middleware: vec![],
        plugins: vec![plugin(&wasm, Some(0))],
        ..Default::default()
    }
    .validate()
    .expect_err("fuel=0 应被拦截");
    assert!(err.to_string().contains("fuel"), "{err}");

    // deny_unknown_fields：未知字段拦截
    let err = serde_yaml::from_str::<ObfsPluginConfig>("path: /tmp/x.wasm\nbogus: 1\n")
        .expect_err("未知字段应被拒");
    assert!(err.to_string().contains("unknown field"), "{err}");

    std::fs::remove_file(&wasm).ok();
}
