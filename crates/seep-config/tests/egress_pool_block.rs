//! P1-5 egress-connection-pool.md §8.1（M1 schema 半边）：egress_pool 块——
//! 存量零差异 / 缺省值 / deny 收口 / 往返 / validate 四规则两态。
//! 转换半边见 seep-runtime `pool_config.rs`。

use seep_config::{EgressPoolBlock, SeepConfig};

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

/// §3.4：存量配置无 egress_pool: → None，行为零差异；含块可解析且
/// §3.1 缺省值正确（enabled=false / tls_resumption=true / 其余 None→缺省）。
#[test]
fn egress_pool_block_defaults_backward_compatible() {
    let cfg: SeepConfig = serde_yaml::from_str(BASE_YAML).expect("无 egress_pool 块应可解析");
    assert_eq!(cfg.egress_pool, None, "存量配置 egress_pool 应为 None");

    let yaml = format!("{BASE_YAML}egress_pool:\n  enabled: true\n");
    let cfg: SeepConfig = serde_yaml::from_str(&yaml).expect("含 egress_pool 块应可解析");
    let block = cfg.egress_pool.expect("egress_pool 块应存在");
    assert!(block.enabled);
    assert!(
        block.tls_resumption(),
        "tls_resumption 缺省 true（块存在即生效，§3.1）"
    );
    assert_eq!(block.max_idle_per_key, None);
    assert_eq!(
        block.max_idle_global, None,
        "D-8：未写 → 取 connection_pool_size"
    );
    assert_eq!(block.low_watermark, None);
    assert_eq!(block.idle_timeout_secs, None);
    assert_eq!(block.dial_timeout_secs, None);
    assert_eq!(block.session_cache_size, None);
    assert!(
        !block.pre_dial_direct(),
        "pre_dial_direct 缺省 false（R-pool2）"
    );

    // 关闭态（enabled 缺省 false）：块存在仍生效 TLS 恢复半边（§4.1 filter 口径）
    let yaml = format!("{BASE_YAML}egress_pool:\n  max_idle_per_key: 4\n");
    let cfg: SeepConfig = serde_yaml::from_str(&yaml).expect("关闭态含容量字段应可解析");
    let block = cfg.egress_pool.expect("块应存在");
    assert!(!block.enabled);
    assert!(
        block.tls_resumption(),
        "仅写容量字段不影响 tls_resumption 缺省"
    );
    assert_eq!(block.max_idle_per_key, Some(4));
}

/// §3.4：块级 deny_unknown_fields——拼错子字段构建期即报（新块无存量负担）。
#[test]
fn egress_pool_block_denies_unknown_fields() {
    let yaml = "enabled: false\nmax_idle_per_keyy: 2\n";
    let err = serde_yaml::from_str::<EgressPoolBlock>(yaml).expect_err("未知子字段应被 deny 拒绝");
    assert!(err.to_string().contains("unknown field"), "{err}");

    // 往返：全字段块 → YAML → 等价还原
    let block = EgressPoolBlock {
        enabled: true,
        tls_resumption: Some(false),
        max_idle_per_key: Some(4),
        max_idle_global: Some(2048),
        low_watermark: Some(2),
        idle_timeout_secs: Some(60),
        dial_timeout_secs: Some(3),
        session_cache_size: Some(128),
        pre_dial_direct: Some(true),
    };
    let raw = serde_yaml::to_string(&block).expect("序列化");
    let back: EgressPoolBlock = serde_yaml::from_str(&raw).expect("反序列化");
    assert_eq!(back, block, "全字段往返等价");
    assert!(
        raw.contains("max_idle_global: 2048"),
        "snake_case 键形：{raw}"
    );
}

/// §3.3-1：池与 TLS 恢复全关 → 后续容量/水位坏值无视（容忍半成品）。
#[test]
fn validate_all_disabled_tolerates_half_config() {
    let block: EgressPoolBlock = serde_yaml::from_str(
        "enabled: false\ntls_resumption: false\nmax_idle_per_key: 0\nlow_watermark: 99\n\
         session_cache_size: 0\npre_dial_direct: true\n",
    )
    .expect("解析");
    block.validate().expect("全关容忍半成品（§3.3-1）");
}

/// §3.3-2 E1 三态 + 开关矩阵：max_idle_per_key=0 / low_watermark 越界 /
/// session_cache_size=0（resumption 开拦、关放）；§3.3-4 两态。
#[test]
fn validate_rule_matrix() {
    // E1：max_idle_per_key = 0
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\nmax_idle_per_key: 0\n").expect("解析");
    let err = block.validate().expect_err("0 上限应拦");
    assert!(err.to_string().contains("max_idle_per_key"), "{err:#}");

    // E1：low_watermark > max_idle_per_key（显式两值）
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\nlow_watermark: 3\nmax_idle_per_key: 2\n")
            .expect("解析");
    let err = block.validate().expect_err("水位越界应拦");
    assert!(err.to_string().contains("low_watermark"), "{err:#}");

    // E1：low_watermark > 缺省 max_idle_per_key=2
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\nlow_watermark: 3\n").expect("解析");
    assert!(block.validate().is_err(), "对缺省上限校验");

    // E1：session_cache_size = 0 且 tls_resumption 开（缺省开）
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\nsession_cache_size: 0\n").expect("解析");
    let err = block.validate().expect_err("零容量缓存应拦");
    assert!(err.to_string().contains("session_cache_size"), "{err:#}");

    // 同值但 tls_resumption 关 → 放行（缓存不启用）
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\ntls_resumption: false\nsession_cache_size: 0\n")
            .expect("解析");
    block.validate().expect("resumption 关时零缓存不拦");

    // §3.3-4：pre_dial_direct=true 无池 → Err
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: false\npre_dial_direct: true\n").expect("解析");
    let err = block.validate().expect_err("无池预拨应拦");
    assert!(err.to_string().contains("pre_dial_direct"), "{err:#}");

    // 搭配 enabled=true → 放行
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\npre_dial_direct: true\n").expect("解析");
    block.validate().expect("开池预拨放行");

    // §3.3-3：idle_timeout < dial_timeout → 不 Err（warning 落转换处）
    let block: EgressPoolBlock =
        serde_yaml::from_str("enabled: true\nidle_timeout_secs: 2\ndial_timeout_secs: 5\n")
            .expect("解析");
    block.validate().expect("warning 不 Err");

    // 合法边界：显式值全取下界/等值 → 放行
    let block: EgressPoolBlock = serde_yaml::from_str(
        "enabled: true\nmax_idle_per_key: 1\nlow_watermark: 1\nsession_cache_size: 1\n",
    )
    .expect("解析");
    block.validate().expect("下界合法");
}
