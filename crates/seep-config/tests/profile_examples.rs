//! P2-3 scenario-profiles.md §7-6（M1）：示例三选一可运行——三份
//! examples/profile-*.yaml 走 `load_from_path` 全链路（含 apply_profile
//! 展开），并钉住「仅策略差异」口径（control/telemetry/ingress/egress
//! 四块三份全等）。

use seep_config::{ProfileKind, SeepConfig};

fn examples_dir() -> String {
    std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| format!("{d}/../../examples"))
        .expect("CARGO_MANIFEST_DIR 应存在")
}

fn load(name: &str) -> SeepConfig {
    let path = format!("{}/{name}", examples_dir());
    SeepConfig::load_from_path(&path).unwrap_or_else(|e| panic!("{name} 应可加载并展开: {e:#}"))
}

/// 口径 1：三份示例各自走 load_from_path（seepd 同入口）解析 + 展开。
#[test]
fn three_examples_load_and_expand() {
    let proxy = load("profile-proxy.yaml");
    let game = load("profile-game.yaml");
    let web = load("profile-web.yaml");

    assert_eq!(proxy.profile, Some(ProfileKind::Proxy));
    assert_eq!(game.profile, Some(ProfileKind::Game));
    assert_eq!(web.profile, Some(ProfileKind::Web));

    // proxy：auto 组 + cn 规则；obfs/pool 不动
    assert_eq!(proxy.routing.groups[0].name, "auto");
    assert_eq!(proxy.routing.rules[0].name, "cn");
    assert_eq!(proxy.obfuscation, None);
    assert_eq!(proxy.egress_pool, None);

    // game：game-auto 组带 slo + 域名模板规则 + obfs bucket + udp 显式长局
    assert_eq!(game.routing.groups[0].name, "game-auto");
    assert!(game.routing.groups[0].slo.is_some(), "game 带调度目标");
    assert!(game.routing.rules.len() >= 8, "游戏平台域模板");
    let obfs = game.obfuscation.as_ref().expect("game 展开混淆");
    assert!(obfs.enabled);
    let padding = obfs.padding.as_ref().expect("bucket 内联 padding");
    assert_eq!(padding.mode, "bucket");
    assert!(game.udp.enabled, "game 示例显式承载 UDP（§9-1）");
    assert_eq!(game.udp.session_lifetime_secs, Some(3600));
    assert_eq!(game.egress_pool, None);

    // web：web-auto 组 + cn 规则 + pool enabled；obfs/udp 不动
    assert_eq!(web.routing.groups[0].name, "web-auto");
    assert_eq!(web.routing.rules[0].name, "cn");
    assert_eq!(web.obfuscation, None);
    let pool = web.egress_pool.as_ref().expect("web 展开连接池");
    assert!(pool.enabled);
    assert!(!web.udp.enabled, "web 不碰 udp（缺省关）");
}

/// 口径 2：三份示例仅策略差异——control/telemetry/ingress/egress 全等。
#[test]
fn examples_differ_only_in_policy_blocks() {
    let proxy = load("profile-proxy.yaml");
    let game = load("profile-game.yaml");
    let web = load("profile-web.yaml");

    assert_eq!(proxy.control, game.control);
    assert_eq!(proxy.control, web.control);
    assert_eq!(proxy.telemetry, game.telemetry);
    assert_eq!(proxy.telemetry, web.telemetry);
    assert_eq!(proxy.ingress, game.ingress);
    assert_eq!(proxy.ingress, web.ingress);
    assert_eq!(proxy.egress, game.egress);
    assert_eq!(proxy.egress, web.egress);
    assert_eq!(proxy.network, game.network);
    assert_eq!(proxy.network, web.network);

    // 策略面各归各位：game 的 udp 显式块不串入另两份（其余参数全缺省）
    assert_eq!(proxy.udp, seep_config::UdpConfig::default());
    assert_eq!(web.udp, proxy.udp);
    assert_eq!(
        game.udp,
        seep_config::UdpConfig {
            enabled: true,
            session_idle_secs: 300,
            session_lifetime_secs: Some(3600),
            ..seep_config::UdpConfig::default()
        }
    );
}
