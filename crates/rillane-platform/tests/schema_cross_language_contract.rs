//! RIL-083 第三段：schema_v1 跨语言 CI 契约门。
//!
//! `contracts/schema_v1/README.md` 自述五面分别由五个 crate 的门钉死；本门
//! 验证这条声明的结构事实：五个样本文件在场且 `schema_version: 1`；README
//! 点名的五个测试门源码在场且都真的读取对应样本；CI 的工作流确实运行
//! `cargo test --workspace`（门不是只在本地跑的孤儿测试）。
//!
//! 「Rust、宿主桥接和 MCP 工具对同一版本有一致解释」的本地可核验面 = .schema
//! 目录单版本 + 五个门各自 load 同一版本样本 + CI 跑全 workspace 测试；
//! 宿主桥接真机批次 / MCP 官方协议层不在本门（见 schema_v1/README 边界）。

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

#[test]
fn schema_v1_faces_and_gates_are_wired() {
    let gates = [
        (
            "crates/rillane-config/tests/contract_ir_sample.rs",
            "ir_face_v1.json",
        ),
        (
            "crates/rillane-core/tests/contract_trace_face.rs",
            "trace_face_v1.json",
        ),
        ("apps/rillaned/src/control_plane.rs", "control_face_v1.json"),
        (
            "crates/rillane-ffi/tests/contract_query_face.rs",
            "ffi_face_v1.json",
        ),
        (
            "crates/rillane-app/tests/contract_tools_face.rs",
            "mcp_tools_face_v1.json",
        ),
    ];

    // 目录里恰好是这五面：多出样本＝有面没门，少一面＝有门没样本。
    let dir = repo_root("contracts/schema_v1");
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .expect("schema_v1 目录")
        .map(|e| e.expect("条目").file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    let wired: BTreeSet<String> = gates.iter().map(|(_, f)| f.to_string()).collect();
    assert_eq!(on_disk, wired, "schema_v1 样本面与已接线的门不成一一对应");

    let readme = read_text("contracts/schema_v1/README.md");
    for (gate, face) in gates {
        let path = format!("contracts/schema_v1/{face}");
        let raw = read_text(&path);
        let v: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path} JSON 解析失败: {e}"));
        assert_eq!(
            v["schema_version"],
            serde_json::json!(1u32),
            "{path} 版本漂移"
        );
        assert!(
            readme.contains(face) && readme.contains(gate),
            "schema_v1 README 未登记 {face} ↔ {gate} 的门"
        );
        let src = read_text(gate);
        assert!(
            src.contains(face),
            "门 {gate} 未读取 {face}（README 声明的门与实现脱节）"
        );
    }
}

#[test]
fn schema_v1_is_the_only_frozen_directory() {
    let root = repo_root("contracts");
    let mut versions = BTreeSet::new();
    for e in std::fs::read_dir(&root).expect("contracts 目录") {
        let p = e.expect("条目").path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("schema_v") && p.is_dir() {
            versions.insert(name.to_string());
        }
    }
    assert_eq!(
        versions,
        BTreeSet::from(["schema_v1".to_string()]),
        "schema 目录只允许 v1 冻结；升级须整目录复制 + 五门同提交更新"
    );
}

#[test]
fn ci_runs_full_workspace_tests() {
    let mut found = false;
    for workflow in [".github/workflows/ci.yml", ".github/workflows/nightly.yml"] {
        let raw = read_text(workflow);
        // 命令可带 --verbose / --all-features 等修饰——只要求同一行同时出现
        // `cargo test` 与 `--workspace`。
        if raw.lines().any(|l| {
            let l = l.trim();
            l.starts_with("run: cargo test") && l.contains("--workspace")
        }) {
            found = true;
        }
    }
    assert!(
        found,
        "CI 未跑 cargo test --workspace——schema 契约门不在 CI（跨语言门成孤儿）"
    );
}

/// 对账器自证：门源码丢失样本引用 → 本门必须点名失败。
#[test]
#[should_panic(expected = "门 crates/rillane-ffi/tests/contract_query_face.rs 未读取")]
fn comparator_bites_on_unwired_face() {
    let gate = "crates/rillane-ffi/tests/contract_query_face.rs";
    let face = "ffi_face_v1.json";
    let src = read_text(gate).replace(face, "");
    assert!(
        src.contains(face),
        "门 {gate} 未读取 {face}（README 声明的门与实现脱节）"
    );
}
