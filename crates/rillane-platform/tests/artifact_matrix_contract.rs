//! 六平台构建产物矩阵契约（RIL-084）：`contracts/build_matrix_v1.json`
//! 是机器可读真源——目标/最低系统/feature/产物/签名/验证层一表钉死。
//! 本门从 CI workflow、平台 build.sh、README 验真，防止「清单写一套、
//! 产线跑另一套」：
//! - CI `cross check` 与 nightly `cross build` 目标必须被矩阵覆盖
//!   （每个目标必须归属恰一平台，且出现在该平台脚本或产物清单）；
//! - 每个平台目录/脚本/证据文件必须在场；
//! - `release_signed` 恒 false（仓内无签名产物），Android 仅 debug key；
//! - `run_verification` 只允许四个诚实值——`verified_emulator`
//!   （AVD 实测）、`needs_os` / `needs_device` / `needs_signing`（未验）；
//!   cross-check 只证明可编译，绝不冒充运行通过。
//!
//! 验收依赖未决（RIL-036/039/041/042/046/049 真机批次）——本门只钉
//! 本地可核验的产物面，不勾选 RIL-084 运行验收；真机证据出现后须
//! 显式更新矩阵 `run_verification`（本门对语义值域钉死，不会静默
//! 把 needs_* 升成 verified_*）。

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn repo_root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn load_matrix() -> Value {
    let path = repo_root("contracts/build_matrix_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("无法读取构建矩阵 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("构建矩阵 JSON 解析失败: {e}"))
}

/// 从 workflow 文本里提取 `cross check/build --target <目标>` 行里的 ${{ matrix.target }}，
/// 再回到该文件 `target:` 段收集实际三元组值（形如 `  - x86_64-unknown-linux-gnu`）。
fn workflow_targets(path: &str, step_marker: &str) -> BTreeSet<String> {
    let raw =
        std::fs::read_to_string(repo_root(path)).unwrap_or_else(|e| panic!("无法读取 {path}: {e}"));
    assert!(
        raw.contains(step_marker),
        "{path} 缺 {step_marker}（产线步骤被移除 → 矩阵口径需同步）"
    );
    let lines: Vec<&str> = raw.lines().collect();
    let marker_line = lines
        .iter()
        .position(|l| l.contains(step_marker))
        .expect("step_marker 行号");
    // 向前面最近一个 `      matrix:` 倒查，其后连续 `        target:` 段到下一个
    // 同级 `    steps:` 前的所有 `- <triple>` 都是矩阵值。
    let matrix_line = lines[..marker_line]
        .iter()
        .rposition(|l| l.trim() == "matrix:")
        .expect("workflow matrix 段");
    let targets: BTreeSet<String> = lines[matrix_line..marker_line]
        .iter()
        .filter_map(|l| {
            let trimmed = l.trim();
            let val = trimmed.strip_prefix("- ")?;
            if val.starts_with("x86_64-")
                || val.starts_with("aarch64-")
                || val.starts_with("armv7-")
            {
                Some(val.trim().to_string())
            } else {
                None
            }
        })
        .collect();
    assert!(!targets.is_empty(), "{path} matrix 内未提取到目标三元组");
    targets
}

fn script_text(rel: &str) -> String {
    let p = repo_root(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("无法读取平台脚本 {}: {e}", p.display()))
}

#[test]
fn build_matrix_covers_ci_and_nightly_targets() {
    let matrix = load_matrix();
    assert_eq!(matrix["schema_version"], serde_json::json!(1u32));
    let platforms = matrix["platforms"].as_object().expect("platforms 对象");
    assert_eq!(platforms.len(), 6, "六平台恰好六个条目");

    // 每个目标的唯一归属：CI/nightly 目标 → 至少一平台声明支持。
    let mut known: BTreeMap<String, String> = BTreeMap::new();
    for (key, p) in platforms {
        for t in p["triples"].as_array().expect("triples 数组") {
            let t = t.as_str().expect("三元组字符串");
            let prior = known.insert(t.to_string(), key.to_string());
            assert!(prior.is_none(), "目标 {t} 被 {key} 与 {prior:?} 重复登记");
        }
    }

    for (label, (path, marker)) in [
        (
            "CI cross check",
            (
                ".github/workflows/ci.yml",
                "run: cross check --target ${{ matrix.target }}",
            ),
        ),
        (
            "nightly cross build",
            (
                ".github/workflows/nightly.yml",
                "run: cross build --release --target ${{ matrix.target }} --workspace",
            ),
        ),
    ] {
        for t in workflow_targets(path, marker) {
            assert!(
                known.contains_key(&t),
                "{label} 目标 {t} 未登记在 build_matrix_v1.json（清单落后于产线）"
            );
        }
    }

    // 每个平台的产物目标 ⊆ 声明目标；ci_check_only 与产物目标不重叠
    // （既有交叉编译门禁不冒充交付产物）。
    for (key, p) in platforms {
        let triples: BTreeSet<&str> = p["triples"]
            .as_array()
            .expect("triples")
            .iter()
            .map(|v| v.as_str().expect("str"))
            .collect();
        let artifacts: BTreeSet<&str> = p["artifact_triples"]
            .as_array()
            .expect("artifact_triples")
            .iter()
            .map(|v| v.as_str().expect("str"))
            .collect();
        let check_only: BTreeSet<&str> = p["ci_check_only_triples"]
            .as_array()
            .expect("ci_check_only_triples")
            .iter()
            .map(|v| v.as_str().expect("str"))
            .collect();
        assert!(
            artifacts.is_subset(&triples),
            "{key} 产物目标 {artifacts:?} 不在声明目标内"
        );
        assert!(
            check_only.is_subset(&triples),
            "{key} 仅检查目标 {check_only:?} 不在声明目标内"
        );
        assert!(
            artifacts.is_disjoint(&check_only),
            "{key} 同一目标既算产物又算仅检查（cross-check 冒充运行/交付证据）"
        );
    }
}

#[test]
fn platform_files_and_build_scripts_exist() {
    let matrix = load_matrix();
    for (key, p) in matrix["platforms"].as_object().expect("platforms") {
        let dir = p["directory"].as_str().expect("directory");
        assert!(repo_root(dir).is_dir(), "{key} 平台目录 {dir} 不存在");
        let script = p["build_script"].as_str().expect("build_script");
        assert!(
            repo_root(script).is_file(),
            "{key} 构建脚本 {script} 不存在"
        );
        for ev in p["evidence"].as_array().expect("evidence") {
            let ev = ev.as_str().expect("str");
            assert!(repo_root(ev).is_file(), "{key} 证据文件 {ev} 不存在");
        }
        // 产物目标必须在脚本或其 README 中被点名——清单不能凭空列目标。
        let text = format!(
            "{}{}",
            script_text(script),
            script_text(&format!("{dir}/README.md"))
        );
        for t in p["artifact_triples"].as_array().expect("artifact_triples") {
            let t = t.as_str().expect("str");
            assert!(
                text.contains(t),
                "{key} 产物目标 {t} 未在 {script} 或 {dir}/README.md 出现"
            );
        }
    }
}

#[test]
fn honest_signing_and_verification_boundaries() {
    let matrix = load_matrix();
    for (key, p) in matrix["platforms"].as_object().expect("platforms") {
        let s = &p["signing"];
        assert_eq!(
            s["release_signed"], false,
            "{key} release_signed=true——仓内无签名产物，须附签名证据才允许改"
        );
        assert!(
            !s["detail"].as_str().expect("detail").is_empty(),
            "{key} 签名边界缺具名说明"
        );
        // Android 是唯一 debug-key 面（debug APK）；其余不得借调试签名冒充签名产物。
        assert_eq!(
            s["debug_key_only"],
            key == "android",
            "{key} debug_key_only 与已知产物形态不符"
        );
        let verification = p["run_verification"].as_str().expect("run_verification");
        assert!(
            matches!(
                verification,
                "verified_emulator" | "needs_os" | "needs_device" | "needs_signing"
            ),
            "{key} run_verification={verification:?} 不在诚实值域"
        );
        assert!(
            !p["run_note"].as_str().expect("run_note").is_empty(),
            "{key} 运行验收边界缺具名说明"
        );
    }
    // 已知唯一实测面是 Android AVD（ICMP 回环，不含完整转发）；其余三态
    // 不得静默升格——这条断言把「不把 cross-check 当运行通过」钉死。
    let android = &matrix["platforms"]["android"];
    assert_eq!(
        android["run_verification"], "verified_emulator",
        "Android AVD 实测面变更须同步契约（升级/降级都显式）"
    );
    for key in [
        "linux-systemd",
        "openwrt",
        "windows",
        "macos-launchd",
        "ios",
    ] {
        assert_ne!(
            matrix["platforms"][key]["run_verification"], "verified_emulator",
            "{key} 无真机证据不得标实测"
        );
    }
}

/// RIL-042：不支持的架构必须**具名 + 根因 + 重开条件**入账，且不能
/// 以「未支持」掩盖为已交付产物——本门从 build.sh/README 的既有说明核读。
#[test]
fn openwrt_unsupported_architectures_are_named_with_reopen_conditions() {
    let matrix = load_matrix();
    let entry = &matrix["platforms"]["openwrt"];
    let unsupported = entry["unsupported_architectures"]
        .as_array()
        .expect("openwrt 须显式列 unsupported_architectures");
    assert!(!unsupported.is_empty(), "不支持架构不得空列");
    let script = script_text(entry["build_script"].as_str().expect("build_script"));
    let readme = script_text("platforms/openwrt/README.md");
    for item in unsupported {
        let arch = item["arch"].as_str().expect("arch");
        let reason = item["reason"].as_str().expect("reason");
        let reopen = item["reopen"].as_str().expect("reopen");
        assert!(
            !reason.is_empty() && !reopen.is_empty(),
            "{arch} 缺根因/重开条件"
        );
        // 每条至少在 build.sh 或 README 有出处（机器账本不只靠单方声明）。
        assert!(
            (script.contains("mips") || readme.contains("mips")) && arch.contains("mips")
                || (script.contains("armv7") || readme.contains("armv7")) && arch.contains("armv7"),
            "{arch} 在 build.sh/README 无可核出处"
        );
        // 不支持的架构绝不能登记为产物目标（清单自相矛盾）。
        for t in entry["artifact_triples"]
            .as_array()
            .expect("artifact_triples")
        {
            let t = t.as_str().expect("str");
            if arch.contains(t.split('-').next().unwrap_or("")) {
                // armv7 triple 的「未成功交叉」必须有 ci_check_only 或显式产物边界；
                // 当前 build.sh 的缺省矩阵列 armv7，但对应 ipk 未在产物
                // 清单中交付，故 run_verification 必须仍为 needs_device。
                assert_eq!(
                    entry["run_verification"], "needs_device",
                    "{t} 交叉失败而 run_verification 已升格"
                );
            }
        }
    }
}

/// 对账器自证：篡改矩阵（伪造 macOS 已验）→ 本门必须点名失败
/// （防止值域断言被静默绕过）。
#[test]
#[should_panic(expected = "macos-launchd 无真机证据不得标实测")]
fn comparator_bites_on_faked_device_evidence() {
    let mut matrix = load_matrix();
    matrix["platforms"]["macos-launchd"]["run_verification"] =
        serde_json::json!("verified_emulator");
    for key in [
        "linux-systemd",
        "openwrt",
        "windows",
        "macos-launchd",
        "ios",
    ] {
        assert_ne!(
            matrix["platforms"][key]["run_verification"], "verified_emulator",
            "{key} 无真机证据不得标实测"
        );
    }
}

/// 对账器自证：删掉 unsupported_architectures → 本门必须点名失败。
#[test]
#[should_panic(expected = "openwrt 须显式列 unsupported_architectures")]
fn comparator_bites_on_dropped_unsupported_architecture_list() {
    let mut matrix = load_matrix();
    matrix["platforms"]["openwrt"]
        .as_object_mut()
        .expect("openwrt object")
        .remove("unsupported_architectures");
    let entry = &matrix["platforms"]["openwrt"];
    let _ = entry["unsupported_architectures"]
        .as_array()
        .expect("openwrt 须显式列 unsupported_architectures");
}

// —— RIL-084 第二段：构建日志与依赖可复核 ——

/// 根 Cargo.toml [patch.crates-io] 申报的 git 来源（`git+<url>?rev=<rev>` 前缀）。
fn declared_patch_git_sources() -> BTreeSet<String> {
    let root = script_text("Cargo.toml");
    let patch = root
        .split("\n[patch.crates-io]")
        .nth(1)
        .expect("根 Cargo.toml 缺 [patch.crates-io] 段（段头须顶格）");
    let patch: String = patch
        .split('\n')
        .take_while(|l| !l.starts_with('['))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = BTreeSet::new();
    for line in patch.lines() {
        if line.contains("git = \"") {
            let url = line
                .split("git = \"")
                .nth(1)
                .expect("git url")
                .split('"')
                .next()
                .expect("闭合引号");
            let rev = line
                .split("rev = \"")
                .nth(1)
                .expect("rev")
                .split('"')
                .next()
                .expect("闭合引号");
            out.insert(format!("git+{url}?rev={rev}"));
        }
    }
    assert!(!out.is_empty(), "[patch.crates-io] 段未解析到任何 git 申报");
    out
}

fn lock_git_sources_and_registry_counts() -> (BTreeSet<String>, usize, usize) {
    let lock = script_text("Cargo.lock");
    let mut git = BTreeSet::new();
    let mut registry = 0usize;
    let mut checksums = 0usize;
    for line in lock.lines() {
        let line = line.trim();
        if let Some(src) = line.strip_prefix("source = \"") {
            let src = src.trim_end_matches('"');
            if src.starts_with("registry+") {
                registry += 1;
            } else {
                git.insert(src.to_string());
            }
        } else if line.starts_with("checksum = \"") {
            checksums += 1;
        }
    }
    (git, registry, checksums)
}

fn assert_provenance_matches_declaration(
    declared: &BTreeSet<String>,
    actual_git: &BTreeSet<String>,
    registry: usize,
    checksums: usize,
) {
    for s in actual_git {
        assert!(
            declared.iter().any(|d| s.starts_with(d.as_str())),
            "Cargo.lock 出现未申报来源 {s}（依赖不可复核：新 git 来源须进 [patch.crates-io] 钉 rev）"
        );
    }
    for d in declared {
        assert!(
            actual_git.iter().any(|s| s.starts_with(d.as_str())),
            "[patch.crates-io] 申报 {d} 未落在 Cargo.lock（申报与锁漂移）"
        );
    }
    assert_eq!(
        registry, checksums,
        "registry 依赖 {registry} 个但 checksum {checksums} 条（来源完整性不可复核）"
    );
}

/// 依赖可复核：Cargo.lock 的每一个非 registry 来源都必须是根 Cargo.toml
/// [patch.crates-io] 申报过的（当前恰好一个：rustls fork 钉 rev）；
/// registry 依赖逐个带 checksum；workspace 成员逐个落锁且版本与
/// [workspace.package].version 一致。
#[test]
fn dependency_provenance_is_reviewable() {
    let declared = declared_patch_git_sources();
    let (actual_git, registry, checksums) = lock_git_sources_and_registry_counts();
    assert_provenance_matches_declaration(&declared, &actual_git, registry, checksums);

    let root = script_text("Cargo.toml");
    let ws_version = root
        .split("[workspace.package]")
        .nth(1)
        .expect("根 Cargo.toml 缺 [workspace.package]")
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .expect("[workspace.package] 缺 version")
        .split('"')
        .next()
        .expect("闭合引号");
    let members_block: String = root
        .split("members = [")
        .nth(1)
        .expect("根 Cargo.toml 缺 members")
        .split(']')
        .next()
        .expect("闭合")
        .to_string();
    let lock = script_text("Cargo.lock");
    for member_line in members_block.lines() {
        let dir = member_line.trim().trim_end_matches(',').trim_matches('"');
        if dir.is_empty() {
            continue;
        }
        let manifest = script_text(&format!("{dir}/Cargo.toml"));
        let name = manifest
            .lines()
            .find_map(|l| l.strip_prefix("name = \""))
            .expect("成员缺 name")
            .split('"')
            .next()
            .expect("闭合引号");
        assert!(
            lock.contains(&format!("name = \"{name}\"")),
            "workspace 成员 {name}（{dir}）未落在 Cargo.lock（依赖树不可复核）"
        );
        let block = lock
            .split(&format!("name = \"{name}\""))
            .nth(1)
            .expect("成员锁块")
            .lines()
            .find(|l| !l.trim().is_empty())
            .expect("版本行");
        assert!(
            block.contains(&format!("version = \"{ws_version}\"")),
            "成员 {name} 锁定版本 {block:?} 与 workspace 版本 {ws_version} 漂移"
        );
    }
}

/// 构建日志可复核：矩阵声称「日志落 .build-log.txt」的平台，其 build.sh
/// 必须真的写该日志（声明 ⊆ 脚本；脚本多写不罚）。
#[test]
fn build_log_claims_are_backed_by_scripts() {
    let matrix = load_matrix();
    assert_log_claims_backed(&matrix);
}

fn assert_log_claims_backed(matrix: &Value) {
    for (key, p) in matrix["platforms"].as_object().expect("platforms") {
        let evidence = p["build_evidence"].as_str().expect("build_evidence");
        let script = script_text(p["build_script"].as_str().expect("build_script"));
        assert!(
            !evidence.contains(".build-log") || script.contains(".build-log"),
            "{key} 矩阵声称日志落 .build-log.txt 但 build.sh 不写（构建日志不可复核）"
        );
    }
}

/// 对账器自证（RIL-084 第二段）：给不写日志的平台注入日志声称 → 必须点名。
#[test]
#[should_panic(expected = "ios 矩阵声称日志落 .build-log.txt 但 build.sh 不写")]
fn comparator_bites_on_unbacked_log_claim() {
    let mut matrix = load_matrix();
    matrix["platforms"]["ios"]["build_evidence"] = serde_json::json!("日志落 .build-log.txt");
    assert_log_claims_backed(&matrix);
}

/// 对账器自证（RIL-084 第二段）：Cargo.lock 混入未申报 git 来源 → 必须点名。
#[test]
#[should_panic(expected = "Cargo.lock 出现未申报来源")]
fn comparator_bites_on_undeclared_git_source() {
    let declared = declared_patch_git_sources();
    let mut actual_git = BTreeSet::new();
    actual_git.insert("git+https://example.com/evil?rev=deadbeef".to_string());
    assert_provenance_matches_declaration(&declared, &actual_git, 0, 0);
}
