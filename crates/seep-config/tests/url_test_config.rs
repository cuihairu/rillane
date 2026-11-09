//! PolicyGroup.url_test 配置集成测试（G1-9，reality-vision-outbound.md 及
//! url-test 实测数据面）。
//!
//! 覆盖：serde 缺省值（interval 300s / timeout 5000ms / 组缺 url_test =
//! None）、validate 矩阵（probe host:port / path / interval / timeout）、
//! `RoutingConfig::validate` 逐组调用面。

use seep_config::{RoutingConfig, UrlTestConfig};

fn valid() -> UrlTestConfig {
    UrlTestConfig {
        probe: "www.gstatic.com:80".to_string(),
        path: "/generate_204".to_string(),
        interval_secs: 300,
        timeout_ms: 5000,
    }
}

/// 合法值域通过；serde 缺省面：仅给 probe/path 时 interval 300s、timeout
/// 5000ms；组不带 url_test 键 = None（存量配置零差异）。
#[test]
fn url_test_defaults_and_valid_form() {
    valid().validate("auto").expect("合法值域应通过");

    let src = r#"
default_node: direct
groups:
  - name: auto
    strategy: latency
    members:
      - node-a
    url_test:
      probe: "www.gstatic.com:80"
      path: /generate_204
  - name: plain
    strategy: round_robin
    members:
      - node-a
rules: []
"#;
    let cfg: RoutingConfig = serde_yaml::from_str(src).expect("应可解析");
    let auto = cfg.groups.iter().find(|g| g.name == "auto").unwrap();
    let url_test = auto.url_test.as_ref().expect("url_test 块应在");
    assert_eq!(url_test.interval_secs, 300, "间隔缺省 300s");
    assert_eq!(url_test.timeout_ms, 5000, "超时缺省 5000ms");
    let plain = cfg.groups.iter().find(|g| g.name == "plain").unwrap();
    assert!(plain.url_test.is_none(), "组不带 url_test 键应为 None");
    cfg.validate().expect("全合法应通过 validate");
}

/// probe 值域矩阵：缺 host / 缺端口 / 端口 0 / 非数字端口全拒。
#[test]
fn url_test_probe_matrix() {
    let cases = [
        (":443", "缺 host"),
        ("www.gstatic.com", "缺端口"),
        ("www.gstatic.com:0", "端口不能为 0"),
        ("www.gstatic.com:abc", "端口非法"),
    ];
    for (probe, expect) in cases {
        let mut cfg = valid();
        cfg.probe = probe.to_string();
        let err = cfg.validate("auto").expect_err(probe);
        assert!(
            err.to_string().contains(expect),
            "probe {probe:?} 应报 {expect:?}：{err}"
        );
    }
}

/// path 须以 / 开头；interval_secs / timeout_ms 须 ≥1。
#[test]
fn url_test_path_interval_timeout_matrix() {
    let mut cfg = valid();
    cfg.path = "generate_204".to_string();
    assert!(cfg
        .validate("auto")
        .expect_err("path 缺 / 应拒")
        .to_string()
        .contains("以 / 开头"));

    let mut cfg = valid();
    cfg.interval_secs = 0;
    assert!(cfg
        .validate("auto")
        .expect_err("interval 0 应拒")
        .to_string()
        .contains("≥1"));

    let mut cfg = valid();
    cfg.timeout_ms = 0;
    assert!(cfg
        .validate("auto")
        .expect_err("timeout 0 应拒")
        .to_string()
        .contains("≥1"));
}

/// `RoutingConfig::validate` 逐组调用面：组内 url_test 非法时整配置校验
/// 报错且错误信息带组名。
#[test]
fn routing_config_validate_propagates_url_test_errors() {
    let src = r#"
default_node: direct
groups:
  - name: auto
    strategy: latency
    members:
      - node-a
    url_test:
      probe: "www.gstatic.com:0"
      path: /generate_204
rules: []
"#;
    let cfg: RoutingConfig = serde_yaml::from_str(src).expect("应可解析");
    let err = cfg.validate().expect_err("端口 0 应整配置拒绝");
    assert!(
        err.to_string().contains("auto") && err.to_string().contains("端口不能为 0"),
        "错误应带组名与原因：{err}"
    );
}
