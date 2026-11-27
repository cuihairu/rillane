//! RIL-086 六平台并行场景验收矩阵契约。
//!
//! `contracts/parallel_scenario_matrix_v1.json` 是机器可读真源：真实网站/
//! QUIC 与游戏并行转发矩阵的验收条款 × 六平台，每格只允许四种诚实状态——
//! `verified_local` / `verified_device` / `partial` / `needs_device`。
//!
//! 本门钉住：
//! - 条款集与平台集封闭（与本地可核验面的验收口径一致）；
//! - 每格状态在枚举内，verified 必指向仓内真实存在的证据文件，
//!   needs_device 不得携带证据；
//! - 核心场景「真实网站/QUIC 与游戏并行转发矩阵」六平台不得标
//!   verified_*（协议/调度单测与 ping/curl 单应用面都只是 partial，
//!   不冒充真实网站/QUIC 与游戏并行运行）；
//! - 不支持项拒绝/降级面至少 Linux 与 Windows 有可查证据；
//! - 对账器自证：伪造核心场景实测/伪造 needs 格证据必须点名 panic。

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_matrix() -> Value {
    let path = repo_root("contracts/parallel_scenario_matrix_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取并行场景矩阵 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("并行场景矩阵 JSON 解析失败: {e}"))
}

fn read_text(rel: &str) -> String {
    std::fs::read_to_string(repo_root(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

fn cell(matrix: &Value, clause: &str, platform: &str) -> (String, Vec<String>) {
    let c = &matrix["clauses"][clause]["cells"][platform];
    let status = c["status"]
        .as_str()
        .unwrap_or_else(|| panic!("矩阵缺 {clause}/{platform} 状态"))
        .to_string();
    let evidence: Vec<String> = c["evidence"]
        .as_array()
        .unwrap_or_else(|| panic!("{clause}/{platform} 缺 evidence 数组"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("{clause}/{platform} 证据项非字符串"))
                .to_string()
        })
        .collect();
    (status, evidence)
}

const EXPECTED_PLATFORMS: [&str; 6] = [
    "linux-systemd",
    "openwrt",
    "windows",
    "macos-launchd",
    "android",
    "ios",
];

const EXPECTED_CLAUSES: [&str; 7] = [
    "dual_stack",
    "dns",
    "mtu",
    "network_change",
    "exit_recovery",
    "real_site_quic_game_parallel",
    "unsupported_reject_or_degrade",
];

const CORE_CLAUSE: &str = "real_site_quic_game_parallel";

#[test]
fn matrix_covers_closed_clause_and_platform_sets() {
    let matrix = load_matrix();
    assert_eq!(matrix["schema_version"], serde_json::json!(1u32));
    let platforms: BTreeSet<&str> = matrix["platforms"]
        .as_array()
        .expect("platforms 数组")
        .iter()
        .map(|v| v.as_str().expect("platform 项为字符串"))
        .collect();
    let expected_platforms: BTreeSet<&str> = EXPECTED_PLATFORMS.iter().copied().collect();
    assert_eq!(platforms, expected_platforms, "六平台封闭集");
    let clauses = matrix["clauses"].as_object().expect("clauses 对象");
    let keys: BTreeSet<&str> = clauses.keys().map(String::as_str).collect();
    let expected_clauses: BTreeSet<&str> = EXPECTED_CLAUSES.iter().copied().collect();
    assert_eq!(
        keys, expected_clauses,
        "RIL-086 验收条款封闭集（双栈/DNS/MTU/切网/退出恢复/真实网站 QUIC+游戏并行/拒绝降级）"
    );
    for clause in &EXPECTED_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            assert!(
                clauses[*clause]["cells"][platform].is_object(),
                "条款 {clause} 缺 {platform} 格"
            );
        }
    }
}

#[test]
fn verified_cells_have_evidence_and_needs_have_none() {
    let matrix = load_matrix();
    for clause in &EXPECTED_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            let (status, evidence) = cell(&matrix, clause, platform);
            match status.as_str() {
                "verified_local" | "verified_device" => {
                    assert!(
                        !evidence.is_empty(),
                        "{clause}/{platform} 标 {status} 却无证据——冒充实测"
                    );
                    for ev in &evidence {
                        assert!(
                            repo_root(ev).is_file(),
                            "{clause}/{platform} 证据文件 {ev} 不存在"
                        );
                    }
                }
                "partial" => {
                    // 部分面可引用真实文件，但每条证据必须实际存在。
                    for ev in &evidence {
                        assert!(
                            repo_root(ev).is_file(),
                            "{clause}/{platform} partial 证据文件 {ev} 不存在"
                        );
                    }
                }
                "needs_device" => {
                    assert!(
                        evidence.is_empty(),
                        "{clause}/{platform} 状态 needs_device 不得携带证据——避免把构建/check-only 升格为验收"
                    );
                }
                other => panic!("{clause}/{platform} 状态 {other:?} 不在四值诚实枚举内"),
            }
        }
    }
}

#[test]
fn core_parallel_scenario_never_verified() {
    let matrix = load_matrix();
    for platform in &EXPECTED_PLATFORMS {
        let (status, _) = cell(&matrix, CORE_CLAUSE, platform);
        assert!(
            status == "partial" || status == "needs_device",
            "核心场景 {CORE_CLAUSE}/{platform} 标 {status}——真实网站/QUIC 与游戏并行转发\
             真机矩阵六平台均未跑；协议/调度单测与 ping/curl 单应用面只算 partial"
        );
    }
    // 协议/调度单测与真实浏览器/游戏并行运行不得混同：Windows 仅有
    // ping/curl 单应用入环证据，核心场景同样只能标 partial。
    assert_eq!(
        cell(&matrix, CORE_CLAUSE, "windows").0,
        "partial",
        "Windows 核心场景只能 partial（curl/ping 单应用面，非并行矩阵）"
    );
}

#[test]
fn unsupported_reject_and_degrade_has_real_evidence() {
    let matrix = load_matrix();
    for platform in ["linux-systemd", "windows"] {
        let (status, evidence) = cell(&matrix, "unsupported_reject_or_degrade", platform);
        assert!(
            status.starts_with("verified_") && !evidence.is_empty(),
            "不支持项拒绝/降级面 {platform} 至少要有可查证据（{status}）"
        );
    }
}

/// Linux 双栈格的已升格状态必须有真实可跑的运行时证据文件，且源码中
/// 真的发起 IPv4/IPv6 两个 ATYP 的双栈转发（不是纯文本门冒充实测）。
#[test]
#[cfg(target_os = "linux")]
fn linux_dual_stack_cell_points_at_real_runtime_test() {
    let matrix = load_matrix();
    let (status, evidence) = cell(&matrix, "dual_stack", "linux-systemd");
    assert_eq!(status, "verified_local", "Linux 双栈格应为 verified_local");
    assert_eq!(
        evidence.len(),
        2,
        "Linux 双栈应指向配置面 + 运行时实测两份证据"
    );
    let src = read_text(&evidence[1]);
    assert!(
        src.contains("#[tokio::test]")
            && src.contains("0x04")
            && src.contains("Ipv6Addr::LOCALHOST")
            && src.contains("tokio::join!"),
        "Linux 双栈证据 {} 未含真实 IPv6 ATYP 并行往返测试形态",
        evidence[1]
    );
}

/// 对账器自证：把 Linux 双栈格降回 partial → 本门须点名。
#[test]
#[cfg(target_os = "linux")]
#[should_panic(expected = "Linux 双栈格应为 verified_local")]
fn comparator_bites_on_stale_linux_dual_stack_cell() {
    let mut matrix = load_matrix();
    matrix["clauses"]["dual_stack"]["cells"]["linux-systemd"]["status"] =
        serde_json::json!("partial");
    let (status, _) = cell(&matrix, "dual_stack", "linux-systemd");
    assert_eq!(status, "verified_local", "Linux 双栈格应为 verified_local");
}

/// 对账器自证：伪造核心场景 Windows 实测 → 必须点名 panic。
#[test]
#[should_panic(expected = "真机矩阵六平台均未跑")]
fn comparator_bites_on_faked_parallel_matrix() {
    let mut matrix = load_matrix();
    matrix["clauses"][CORE_CLAUSE]["cells"]["windows"]["status"] =
        serde_json::json!("verified_device");
    matrix["clauses"][CORE_CLAUSE]["cells"]["windows"]["evidence"] =
        serde_json::json!(["docs/acceptance-evidence/ril-033-windows-takeover.md"]);
    for platform in &EXPECTED_PLATFORMS {
        let (status, _) = cell(&matrix, CORE_CLAUSE, platform);
        assert!(
            status == "partial" || status == "needs_device",
            "核心场景 {CORE_CLAUSE}/{platform} 标 {status}——真实网站/QUIC 与游戏并行转发\
             真机矩阵六平台均未跑；协议/调度单测与 ping/curl 单应用面只算 partial"
        );
    }
}

/// 对账器自证：needs_device 格塞构建矩阵证据冒充验收 → 必须点名 panic。
#[test]
#[should_panic(expected = "不得携带证据——避免把构建/check-only 升格为验收")]
fn comparator_bites_on_faked_build_evidence() {
    let mut matrix = load_matrix();
    matrix["clauses"]["dual_stack"]["cells"]["ios"]["evidence"] =
        serde_json::json!(["docs/acceptance-evidence/ril-084-artifact-matrix.md"]);
    for clause in &EXPECTED_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            let (status, evidence) = cell(&matrix, clause, platform);
            if status == "needs_device" {
                assert!(
                    evidence.is_empty(),
                    "{clause}/{platform} 状态 needs_device 不得携带证据——避免把构建/check-only 升格为验收"
                );
            }
        }
    }
}
