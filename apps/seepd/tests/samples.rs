//! P0-5 §10-S6 样例防漂移测试：仓库样例即文档，坏样例/坏面板在构建期即红。

use seep_config::SeepConfig;

/// 相对仓库根的样例路径（测试运行于 target/ 之下，CARGO_MANIFEST_DIR = apps/seepd）
fn repo_root(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// S6 测试 1：dashboard JSON 可解析 + 含 `seep_udp_` 查询串（防手改坏 JSON/漏序列，
/// 验收 #3）。逐序列断言 S4 定稿名——四行面板全部入板。
#[test]
fn grafana_dashboard_json_parses() {
    let path = repo_root("docs/grafana/seep-dashboard.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取 {}: {e}", path.display()));
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("dashboard JSON 解析失败: {e}"));

    let exprs: Vec<String> = v["panels"]
        .as_array()
        .expect("panels 数组")
        .iter()
        .filter_map(|p| p["targets"].as_array())
        .flatten()
        .filter_map(|t| t["expr"].as_str().map(str::to_string))
        .collect();

    for series in [
        // 行 1「UDP 会话」
        "seep_udp_sessions_active",
        "seep_udp_associates_active",
        "seep_udp_mappings_active",
        // 行 2「UDP 流量」
        "seep_udp_relay_bytes_total",
        "seep_udp_relay_packets_total",
        // 行 3「UDP 质量」
        "seep_udp_dropped_total",
        "seep_udp_expired_total",
        "seep_udp_reroutes_total",
        // 行 4「mesh UDP」
        "seep_udp_mesh_flows_active",
        "seep_udp_mesh_forwarded_total",
        "seep_udp_mesh_unknown_flow_total",
        "seep_udp_mesh_client_dropped_total",
    ] {
        assert!(
            exprs.iter().any(|e| e.contains(series)),
            "面板查询串缺 {series}"
        );
    }
}

/// S6 测试 2：示例配置全文经 SeepConfig 解析 + validate 成功（样例即文档，坏样例
/// 构建期即红，验收 #1/#7 的样例半边）。样例 `udp:` 块保持 enabled=false——与
/// 「缺省关闭」口径一致，字段语义以注释给全。
#[test]
fn sample_config_parses_with_udp_block() {
    let path = repo_root("config/seep.yaml");
    let cfg = SeepConfig::load_from_path(&path).unwrap_or_else(|e| panic!("样例配置解析失败: {e}"));
    cfg.udp
        .validate()
        .unwrap_or_else(|e| panic!("样例 udp 块未过 validate: {e}"));
    assert!(
        !cfg.udp.enabled,
        "样例 udp.enabled 应保持 false（缺省关闭）"
    );
    // 非活跃字段走 serde default——与 S0 缺省常量一致即合法
    assert_eq!(cfg.udp.max_associates, 256);
    assert_eq!(cfg.udp.sweep_interval_secs, 15);
    assert_eq!(cfg.udp.downlink_queue_depth, 64);
}
