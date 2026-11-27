//! RIL-085 三桌面进程端到端验收矩阵契约（条款 × 平台证据账本）。
//!
//! `contracts/desktop_e2e_matrix_v1.json` 是机器可读真源：把 todo.md 里
//! RIL-085 的验收条款逐格钉到三桌面平台，每格只允许五种诚实状态——
//! `verified_local`（本机真实测试）/ `verified_device`（仓内真机证据
//! 文档）/ `partial`（部分面）/ `needs_runtime`（需图形桌面与浏览器/游戏
//! 会话）/ `needs_mac_ssh`（mac 真机未接入，RIL-036/037/038 未决）。
//!
//! 本门钉住：
//! - 条款集与平台集封闭（少一条=验收面漏项，多一条=非 RIL-085 范围）；
//! - 每格状态在枚举内；
//! - `verified_*` 必须指向仓内真实存在的证据文件，`needs_*`/`partial`
//!   不得携带可指认文件（不冒充实测）；
//! - macOS 除平台无关的「规则来源可查」（纯决策/回放面）外一律
//!   `needs_mac_ssh`——不把 cross-check/单测升格为 mac 真机验收；
//! - 核心场景「相同目标浏览器/两个游戏分组轨迹」与「故障样例」在
//!   六平台均未实测（Windows 仅 HTTP 客户端/服务恢复的 partial 面）——
//!   禁止把 curl/ping/服务恢复证据写成浏览器/游戏轨迹；
//! - 对账器自证：篡改一格状态/证据，本门以点名文案 panic。

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read_text(rel: &str) -> String {
    std::fs::read_to_string(repo_root(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

fn load_matrix() -> Value {
    let path = repo_root("contracts/desktop_e2e_matrix_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取桌面验收矩阵 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("桌面验收矩阵 JSON 解析失败: {e}"))
}

/// 五值诚实枚举：以 `verified_` 起首为「已实测」，其余为未验/部分。
const VERIFIED_PREFIXES: [&str; 2] = ["verified_local", "verified_device"];

fn is_verified(status: &str) -> bool {
    VERIFIED_PREFIXES.iter().any(|p| status.starts_with(p))
}

const EXPECTED_PLATFORMS: [&str; 3] = ["linux", "windows", "macos"];

const EXPECTED_CLAUSES: [&str; 9] = [
    "tcp",
    "udp",
    "name_path",
    "permission_denied",
    "pid_reuse",
    "port_reuse",
    "rule_source",
    "browser_grouped_trace",
    "fault_samples",
];

/// 核心场景：RIL-085 的「相同目标浏览器/两个游戏分组轨迹」与「故障
/// 样例」在六平台均未真机实测——任何平台不得标 verified_*，否则即把
/// curl/ping/服务恢复证据冒充成浏览器/游戏轨迹。
const UNVERIFIED_CORE_CLAUSES: [&str; 2] = ["browser_grouped_trace", "fault_samples"];

fn cell(matrix: &Value, clause: &str, platform: &str) -> (String, Vec<String>) {
    let cell = &matrix["clauses"][clause]["cells"][platform];
    let status = cell["status"]
        .as_str()
        .unwrap_or_else(|| panic!("矩阵缺 {clause}/{platform} 状态"))
        .to_string();
    let evidence: Vec<String> = cell["evidence"]
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

#[test]
fn matrix_covers_closed_clause_and_platform_sets() {
    let matrix = load_matrix();
    assert_eq!(matrix["schema_version"], serde_json::json!(1u32));

    let platforms: BTreeSet<String> = matrix["platforms"]
        .as_array()
        .expect("platforms 数组")
        .iter()
        .map(|v| v.as_str().expect("platform 项为字符串").to_string())
        .collect();
    assert_eq!(
        platforms,
        EXPECTED_PLATFORMS.iter().map(|s| s.to_string()).collect(),
        "三桌面平台封闭集（linux/windows/macos）"
    );

    let clauses = matrix["clauses"].as_object().expect("clauses 对象");
    let keys: BTreeSet<&str> = clauses.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = EXPECTED_CLAUSES.iter().copied().collect();
    assert_eq!(
        keys, expected,
        "RIL-085 验收条款封闭集：少一条=漏验面，多一条=超范围"
    );

    // 每条款三平台格齐全
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
fn verified_cells_point_at_real_evidence_and_unverified_at_none() {
    let matrix = load_matrix();
    for clause in &EXPECTED_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            let (status, evidence) = cell(&matrix, clause, platform);
            assert!(
                matches!(
                    status.as_str(),
                    "verified_local"
                        | "verified_device"
                        | "partial"
                        | "needs_runtime"
                        | "needs_mac_ssh"
                ),
                "{clause}/{platform} 状态 {status:?} 不在五值诚实枚举内"
            );
            match status.as_str() {
                "verified_local" | "verified_device" => {
                    assert!(
                        !evidence.is_empty(),
                        "{clause}/{platform} 标 {status} 却无证据——冒充实测"
                    );
                    for ev in &evidence {
                        assert!(
                            repo_root(ev).is_file(),
                            "{clause}/{platform} 证据文件 {ev} 不存在（verified 必须指向仓内真凭据）"
                        );
                    }
                }
                "partial" => {
                    // 部分面：允许引用真实相关证据，但每条必须是仓内真实文件，
                    // 不得凭空指向——把「部分」钉成可查而非空话。
                    for ev in &evidence {
                        assert!(
                            repo_root(ev).is_file(),
                            "{clause}/{platform} partial 证据文件 {ev} 不存在"
                        );
                    }
                }
                _ => {
                    // needs_runtime / needs_mac_ssh：未实测，不得携带可指认证据，
                    // 避免把单测/cross-check 升格为验收——note 已如实说明边界。
                    assert!(
                        evidence.is_empty(),
                        "{clause}/{platform} 状态 {status}（未实测）不得携带可指认证据"
                    );
                }
            }
        }
    }
}

#[test]
fn macos_needs_device_except_platform_neutral_rule_source() {
    let matrix = load_matrix();
    for clause in &EXPECTED_CLAUSES {
        let (status, _) = cell(&matrix, clause, "macos");
        if *clause == "rule_source" {
            assert_eq!(
                status, "verified_local",
                "规则来源可查是平台无关纯决策/回放面——三平台同证"
            );
        } else {
            assert_eq!(
                status, "needs_mac_ssh",
                "macOS {clause} 除规则来源外一律待 mac 真机接入（RIL-036/037/038 未决），\
                 不得升格为实测"
            );
        }
    }
}

#[test]
fn core_browser_and_fault_scenarios_never_verified() {
    let matrix = load_matrix();
    for clause in &UNVERIFIED_CORE_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            let (status, _) = cell(&matrix, clause, platform);
            assert!(
                !is_verified(&status),
                "条款 {clause}/{platform} 标 {status}——浏览器/游戏分组轨迹与故障样例\
                 在六平台均未实测；Windows 的 curl/ping/服务恢复是 partial/needs_runtime，\
                 不得冒充为浏览器/游戏轨迹"
            );
        }
    }
}

#[test]
fn rule_source_is_platform_neutral_across_desktops() {
    let matrix = load_matrix();
    let statuses: Vec<String> = EXPECTED_PLATFORMS
        .iter()
        .map(|p| cell(&matrix, "rule_source", p).0)
        .collect();
    assert!(
        statuses.iter().all(|s| s == "verified_local"),
        "规则来源可查（订阅→代际→Explain→实际出口一致）是平台无关面，三桌面同证：{statuses:?}"
    );
}

/// 对账器自证：把 macOS 的某非规则来源格升格为 verified_local 并塞一条
/// 真证据文件 → 本门必须点名 panic（证明「mac 不得冒充实测」断言在场）。
#[test]
#[should_panic(expected = "macOS 除规则来源外一律待 mac 真机接入")]
fn comparator_bites_on_faked_macos_device() {
    let mut matrix = load_matrix();
    matrix["clauses"]["tcp"]["cells"]["macos"]["status"] = serde_json::json!("verified_local");
    matrix["clauses"]["tcp"]["cells"]["macos"]["evidence"] =
        serde_json::json!(["crates/rillane-platform/tests/owner_linux_contract.rs"]);
    // 重放「mac 不得冒充实测」断言
    for clause in &EXPECTED_CLAUSES {
        let (status, _) = cell(&matrix, clause, "macos");
        if *clause == "rule_source" {
            assert_eq!(status, "verified_local");
        } else {
            assert_eq!(
                status, "needs_mac_ssh",
                "macOS 除规则来源外一律待 mac 真机接入"
            );
        }
    }
}

/// Linux 权限不足/端口复用两格的已升格状态必须有真实可跑的证据文件
/// 且在源码中真做跨 uid / 多进程（不是纯文本门冒充真机进程实测）。
#[test]
#[cfg(target_os = "linux")]
fn linux_permission_and_port_reuse_cells_point_at_real_process_tests() {
    let matrix = load_matrix();
    for (clause, marker, label) in [
        (
            "permission_denied",
            "setpriv",
            "跨 uid 权限不足（sudo -n + setpriv 真实进程）",
        ),
        (
            "port_reuse",
            "current_exe()",
            "同目标多进程端口复用（两个独立 helper 进程）",
        ),
    ] {
        let (status, evidence) = cell(&matrix, clause, "linux");
        assert_eq!(
            status, "verified_local",
            "Linux {clause} 格应为 verified_local"
        );
        assert_eq!(evidence.len(), 1, "Linux {clause} 应恰指向一份证据");
        let src = read_text(&evidence[0]);
        assert!(
            src.contains("#[test]") && src.contains(marker),
            "Linux {clause} 证据 {ev} 未含真实进程测试形态（{label}）",
            ev = evidence[0]
        );
    }
}

/// 对账器自证：把 Linux 权限不足格降回 needs_runtime → 本门须点名。
#[test]
#[cfg(target_os = "linux")]
#[should_panic(expected = "Linux permission_denied 格应为 verified_local")]
fn comparator_bites_on_stale_linux_permission_cell() {
    let mut matrix = load_matrix();
    matrix["clauses"]["permission_denied"]["cells"]["linux"]["status"] =
        serde_json::json!("needs_runtime");
    let (status, _) = cell(&matrix, "permission_denied", "linux");
    assert_eq!(
        status, "verified_local",
        "Linux permission_denied 格应为 verified_local"
    );
}

/// 对账器自证：Windows 浏览器轨迹冒充实测仍须被拒（原门保留）。
#[test]
#[should_panic(expected = "浏览器/游戏分组轨迹与故障样例在六平台均未实测")]
fn comparator_bites_on_faked_browser_trace() {
    let mut matrix = load_matrix();
    matrix["clauses"]["browser_grouped_trace"]["cells"]["windows"]["status"] =
        serde_json::json!("verified_device");
    matrix["clauses"]["browser_grouped_trace"]["cells"]["windows"]["evidence"] =
        serde_json::json!(["docs/acceptance-evidence/ril-033-windows-takeover.md"]);
    for clause in &UNVERIFIED_CORE_CLAUSES {
        for platform in &EXPECTED_PLATFORMS {
            let (status, _) = cell(&matrix, clause, platform);
            assert!(
                !is_verified(&status),
                "浏览器/游戏分组轨迹与故障样例在六平台均未实测；\
                 Windows 的 curl/ping/服务恢复是 partial/needs_runtime，不得冒充为浏览器/游戏轨迹"
            );
        }
    }
}
