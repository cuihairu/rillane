//! egress_pool 配置区块 → 池策略转换（egress-connection-pool.md §3.2）
//!
//! 裁决同 `obfs_config`/`network_config`：seep-config 镜像 serde 类型，转换落
//! 本 crate（`PoolPolicy` 定义在 seep-protocols——该 crate 需 tokio 拨号；
//! seep-runtime 已依赖双 crate，无新依赖边）。`to_pool_policy` 是 §3.2 表
//! 「全字段具值」产物的唯一产地；D-8 映射（max_idle_global 未写 → 取
//! `connection_pool_size`）由调用方传 `default_global` 注入。

use std::time::Duration;

use anyhow::Result;
use tracing::warn;

use seep_config::EgressPoolBlock;
use seep_protocols::PoolPolicy;

/// §3.1 缺省值（转换侧单一出处；serde 侧块字段全 Option 无缺省函数）
const DEFAULT_MAX_IDLE_PER_KEY: usize = 2;
const DEFAULT_LOW_WATERMARK: usize = 1;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_DIAL_TIMEOUT_SECS: u64 = 5;
const DEFAULT_SESSION_CACHE_SIZE: usize = 256;

/// `egress_pool` 块 → 全字段具值的 `PoolPolicy`（§3.2 表）。
///
/// `default_global` = runtime `connection_pool_size`（D-8：块内 max_idle_global
/// 未写时取之；装配侧 `unwrap_or(1024)` 兜底）。validate 未前置直调防御
/// （obfs_config 先例）：build() 侧已校验，直调（测试/未来调用方）仍拦坏值。
pub fn to_pool_policy(block: &EgressPoolBlock, default_global: usize) -> Result<PoolPolicy> {
    block.validate()?;
    let idle_secs = block.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
    let dial_secs = block.dial_timeout_secs.unwrap_or(DEFAULT_DIAL_TIMEOUT_SECS);
    // §3.3-3：idle_timeout < dial_timeout 仅 warning（预热浪费非错误）——
    // seep-config 无 tracing 依赖，warning 落转换处（§3.3 注记）
    if idle_secs < dial_secs {
        warn!(
            idle_timeout_secs = idle_secs,
            dial_timeout_secs = dial_secs,
            "egress_pool.idle_timeout_secs < dial_timeout_secs：idle 条目寿命短于拨号时长，预热浪费（§3.3-3，非错误）"
        );
    }
    Ok(PoolPolicy {
        enabled: block.enabled,
        tls_resumption: block.tls_resumption(),
        max_idle_per_key: block.max_idle_per_key.unwrap_or(DEFAULT_MAX_IDLE_PER_KEY),
        max_idle_global: block.max_idle_global.unwrap_or(default_global),
        low_watermark: block.low_watermark.unwrap_or(DEFAULT_LOW_WATERMARK),
        idle_timeout: Duration::from_secs(idle_secs),
        dial_timeout: Duration::from_secs(dial_secs),
        session_cache_size: block
            .session_cache_size
            .unwrap_or(DEFAULT_SESSION_CACHE_SIZE),
        pre_dial_direct: block.pre_dial_direct(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全缺省块 + D-8 缺省注入：九字段逐一钉形（§8.1 转换缺省填充）。
    #[test]
    fn to_pool_policy_fills_defaults() {
        let block: EgressPoolBlock = serde_yaml::from_str("enabled: true").expect("解析");
        let policy = to_pool_policy(&block, 1024).expect("转换");
        assert!(policy.enabled);
        assert!(
            policy.tls_resumption,
            "tls_resumption 缺省 true（块存在即生效）"
        );
        assert_eq!(policy.max_idle_per_key, 2);
        assert_eq!(
            policy.max_idle_global, 1024,
            "D-8：未写取 connection_pool_size"
        );
        assert_eq!(policy.low_watermark, 1);
        assert_eq!(policy.idle_timeout, Duration::from_secs(30));
        assert_eq!(policy.dial_timeout, Duration::from_secs(5));
        assert_eq!(policy.session_cache_size, 256);
        assert!(!policy.pre_dial_direct);
    }

    /// D-8 两侧：显式 max_idle_global 压过 connection_pool_size；自定义
    /// connection_pool_size 作为缺省注入；显式字段逐项透传。
    #[test]
    fn to_pool_policy_d8_mapping_and_field_passthrough() {
        let block: EgressPoolBlock = serde_yaml::from_str(
            "enabled: true\nmax_idle_global: 2048\nmax_idle_per_key: 4\nlow_watermark: 2\n\
             idle_timeout_secs: 60\ndial_timeout_secs: 3\nsession_cache_size: 128\n\
             pre_dial_direct: true\ntls_resumption: false\n",
        )
        .expect("解析");
        let policy = to_pool_policy(&block, 512).expect("转换");
        assert_eq!(policy.max_idle_global, 2048, "显式块值压过 D-8 缺省");
        assert_eq!(policy.max_idle_per_key, 4);
        assert_eq!(policy.low_watermark, 2);
        assert_eq!(policy.idle_timeout, Duration::from_secs(60));
        assert_eq!(policy.dial_timeout, Duration::from_secs(3));
        assert_eq!(policy.session_cache_size, 128);
        assert!(policy.pre_dial_direct);
        assert!(!policy.tls_resumption);

        let block2: EgressPoolBlock = serde_yaml::from_str("enabled: true").expect("解析");
        let policy2 = to_pool_policy(&block2, 512).expect("转换");
        assert_eq!(
            policy2.max_idle_global, 512,
            "D-8：自定义 connection_pool_size 注入"
        );
    }

    /// validate 未前置直调防御（obfs_config 先例）：坏值直调仍拦，
    /// 错误信息携带原值与规则出处。
    #[test]
    fn to_pool_policy_defends_against_unvalidated_block() {
        let block: EgressPoolBlock =
            serde_yaml::from_str("enabled: true\nmax_idle_per_key: 0\n").expect("解析");
        let err = to_pool_policy(&block, 1024).expect_err("E1 应拦");
        assert!(err.to_string().contains("max_idle_per_key"), "{err:#}");

        let block: EgressPoolBlock =
            serde_yaml::from_str("enabled: true\nlow_watermark: 5\nmax_idle_per_key: 2\n")
                .expect("解析");
        let err = to_pool_policy(&block, 1024).expect_err("水位越界应拦");
        assert!(err.to_string().contains("low_watermark"), "{err:#}");

        let block: EgressPoolBlock =
            serde_yaml::from_str("enabled: false\npre_dial_direct: true\n").expect("解析");
        let err = to_pool_policy(&block, 1024).expect_err("无池预拨应拦");
        assert!(err.to_string().contains("pre_dial_direct"), "{err:#}");
    }

    /// §3.3-3 warning 语义：idle < dial 不 Err（仅转换侧 warn，此处断言放行）。
    #[test]
    fn to_pool_policy_short_idle_is_warning_not_error() {
        let block: EgressPoolBlock =
            serde_yaml::from_str("enabled: true\nidle_timeout_secs: 2\ndial_timeout_secs: 5\n")
                .expect("解析");
        let policy = to_pool_policy(&block, 1024).expect("warning 不 Err");
        assert_eq!(policy.idle_timeout, Duration::from_secs(2));
        assert_eq!(policy.dial_timeout, Duration::from_secs(5));
    }
}
