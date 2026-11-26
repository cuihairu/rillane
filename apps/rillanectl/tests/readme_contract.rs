//! RIL-091 第四段：根 README 与实际产物对齐契约门。
//!
//! 验收条款「README 与实际产物一致」的机器钉法（根 README 在 vitepress
//! 死链检查器之外，仓内 markdown 链接无人验）：
//! 两语 README 的相对链接与图片路径全部真实存在；quickstart 里的
//! `rillanectl -- <cmd>` 都是真实命令面；`cargo run -p` 的包名真实在
//! workspace（apps/rillaned、apps/rillanectl）；「N 项原子任务」计数与
//! todo.md 唯一 RIL 条目数恰等（陈旧计数会被点名）；rillaned 无 flag 面
//! （Cargo.toml 无 clap 依赖）与 README「无 --config 旗标」声明结构性
//! 一致，RILLANE_CONFIG 默认路径在源码在场。
//!
//! 对账器自证：死链接 / 计数漂移，门必须点名失败。

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

fn exists(rel: &str) -> bool {
    repo_root().join(rel).exists()
}

/// 相对链接目标（跳过 http/mailto/锚点）
fn rel_links(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(pos) = rest.find("](") {
        let tail = &rest[pos + 2..];
        if let Some(close) = tail.find(')') {
            let target = &tail[..close];
            let is_external = target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:");
            let is_anchor = target.starts_with('#');
            if !is_external && !is_anchor && !target.is_empty() {
                out.push(target.to_string());
            }
            rest = &tail[close..];
        } else {
            break;
        }
    }
    out
}

/// markdown 链接与图片路径全部真实存在（两语 README）
#[test]
fn readme_links_resolve_to_real_files() {
    for readme in ["README.md", "README.zh.md"] {
        let doc = read_repo(readme);
        let mut targets = rel_links(&doc);
        // 图片 src（相对路径）
        for seg in doc.split("src=\"").skip(1) {
            if let Some(end) = seg.find('"') {
                let src = &seg[..end];
                if !src.starts_with("http") {
                    targets.push(src.to_string());
                }
            }
        }
        assert!(
            !targets.is_empty(),
            "{readme} 链接面不得为空（解析器失效兜底）"
        );
        for t in &targets {
            let path = t.split('#').next().unwrap();
            assert!(
                exists(path),
                "{readme} 链接目标不存在：{t}（根 README 在站点死链检查器之外，须本门验）"
            );
        }
    }
}

/// quickstart 命令面：`rillanectl -- <cmd>` 的 cmd 都是真实命令；
/// `cargo run -p` 的包名真实在 workspace
#[test]
fn readme_quickstart_faces_exist() {
    let top = std::process::Command::new(env!("CARGO_BIN_EXE_rillanectl"))
        .arg("--help")
        .output()
        .expect("起 rillanectl")
        .stdout;
    let help = String::from_utf8(top).expect("UTF-8");
    let mut real_cmds = BTreeSet::new();
    if let Some(section) = help.split("Commands:\n").nth(1) {
        let section = section.split("\n\n").next().expect("Commands 段未闭合");
        for line in section.lines() {
            if let Some(name) = line.trim_start().split_whitespace().next() {
                if name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                    real_cmds.insert(name.to_string());
                }
            }
        }
    }
    assert!(real_cmds.len() > 20, "命令面解析失效兜底");

    for readme in ["README.md", "README.zh.md"] {
        let doc = read_repo(readme);
        for line in doc.lines().filter(|l| l.contains("rillanectl -- ")) {
            let after = line.split("rillanectl -- ").nth(1).unwrap();
            let cmd = after.split_whitespace().next().unwrap();
            if cmd.starts_with('-') {
                continue; // 旗标（如 --help），非命令名
            }
            assert!(
                real_cmds.contains(cmd),
                "{readme} quickstart 命令不在二进制面：{cmd}——README 与实际产物必须一致"
            );
        }
        assert!(
            doc.contains("cargo run -p rillaned") && doc.contains("cargo run -p rillanectl"),
            "{readme} quickstart 应指向真实 workspace 包"
        );
    }
    // 包目录真实在场
    assert!(exists("apps/rillaned/src/main.rs"), "apps/rillaned 应在场");
    assert!(
        exists("apps/rillanectl/src/main.rs"),
        "apps/rillanectl 应在场"
    );
}

/// 「N 项原子任务」计数 ↔ todo.md 唯一 RIL 条目数恰等
#[test]
fn readme_task_count_matches_todo() {
    let todo = read_repo("todo.md");
    let mut ids = BTreeSet::new();
    for line in todo.lines() {
        if let Some(rest) = line
            .strip_prefix("- [ ] **RIL-")
            .or(line.strip_prefix("- [x] **RIL-"))
        {
            if let Some(num) = rest.split(|c: char| !c.is_ascii_digit()).next() {
                if !num.is_empty() {
                    ids.insert(num.to_string());
                }
            }
        }
    }
    let n = ids.len();
    assert!(n > 100, "todo 条目解析失效兜底：{n}");
    assert!(
        read_repo("README.md").contains(&format!("{n} atomic tasks")),
        "README.md 任务计数陈旧：应为 {n}（todo.md 唯一 RIL 条目数）"
    );
    assert!(
        read_repo("README.zh.md").contains(&format!("{n} 项原子实施任务")),
        "README.zh.md 任务计数陈旧：应为 {n}"
    );
}

/// rillaned 无 flag 面：README「无 --config 旗标」声明 ↔ 结构事实
/// （Cargo.toml 无 clap 依赖）；RILLANE_CONFIG 默认路径在源码在场
#[test]
fn readme_rillaned_no_flag_claim_is_structural() {
    let manifest = read_repo("apps/rillaned/Cargo.toml");
    assert!(
        !manifest.contains("clap"),
        "rillaned 不应有 clap 依赖（README 声明其无 --config 旗标的结构依据）"
    );
    let main = read_repo("apps/rillaned/src/main.rs");
    assert!(
        main.contains("RILLANE_CONFIG"),
        "RILLANE_CONFIG 环境变量读取应在场"
    );
    assert!(
        main.contains("\"config/rillane.yaml\""),
        "RILLANE_CONFIG 默认路径 config/rillane.yaml 应在场"
    );
}

// ---------------------------------------------------------------------------
// 对账器自证
// ---------------------------------------------------------------------------

/// 死链接混入 README → 链接门必须点名
#[test]
#[should_panic(expected = "链接目标不存在")]
fn comparator_bites_on_dead_link() {
    let doc = read_repo("README.md").replacen(
        "](docs/architecture.md)",
        "](docs/nonexistent-page.md)",
        1,
    );
    for t in rel_links(&doc) {
        let path = t.split('#').next().unwrap();
        assert!(
            exists(path),
            "链接目标不存在：{t}（根 README 在站点死链检查器之外，须本门验）"
        );
    }
}

/// 计数漂移 → 计数门必须点名（模拟 README 计数未跟上 todo 变化）
#[test]
#[should_panic(expected = "任务计数陈旧")]
fn comparator_bites_on_stale_count() {
    let todo = read_repo("todo.md");
    let mut ids = BTreeSet::new();
    for line in todo.lines() {
        if let Some(rest) = line
            .strip_prefix("- [ ] **RIL-")
            .or(line.strip_prefix("- [x] **RIL-"))
        {
            if let Some(num) = rest.split(|c: char| !c.is_ascii_digit()).next() {
                if !num.is_empty() {
                    ids.insert(num.to_string());
                }
            }
        }
    }
    let n = ids.len();
    // 模拟漂移：README 里的计数被写陈旧（差 1）
    let readme = read_repo("README.md").replacen(
        &format!("{n} atomic tasks"),
        &format!("{} atomic tasks", n - 1),
        1,
    );
    assert!(
        readme.contains(&format!("{n} atomic tasks")),
        "README.md 任务计数陈旧：应为 {n}"
    );
}
