//! RIL-091 第六段：双语功能矩阵与实际产物对齐契约门。
//!
//! 验收条款「中英文功能矩阵、提案和已交付分开」的机器钉法：双语
//! `docs/feature-matrix.md` 的 F-ID 行集恰等（单语沉掉一行即被点名）、
//! 行内链接与引用产物路径真实存在、「提案，未交付」独立成节且四个已知
//! 提案家族只许出现在提案节之后（能力表不得夹带提案措辞）、平台视图与
//! 三份机器账本引用在场。对账器自证：F-ID 漂移、提案措辞混入能力表，
//! 门必须点名失败。
//!
//! 诚实边界：本门钉结构事实（行配对/链接/产物存在/提案隔离）；每格
//! 声明的真假由被引用的契约门与证据文档各自承担，本门不重复裁决。

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

/// markdown 相对链接目标（跳过 http/mailto/锚点）
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

/// 能力行 ID：表格行首格的 `| F-\d\d |`。行首格定义能力身份；单元格
/// 内的交叉引用（如 F-01 → F-13）不算行，另由悬空引用检查裁决。
fn feature_ids(doc: &str) -> Vec<String> {
    doc.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("| F-")?;
            if rest.len() >= 3 {
                let id = &rest[..2];
                if id.bytes().all(|b| b.is_ascii_digit()) && rest[2..].starts_with(" |") {
                    return Some(format!("F-{id}"));
                }
            }
            None
        })
        .collect()
}

/// 全文词边界的 `F-\d\d` 令牌（含单元格内交叉引用）
fn all_f_tokens(doc: &str) -> Vec<String> {
    let bytes = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i] == b'F'
            && bytes[i + 1] == b'-'
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'-'))
            && (i + 4 == bytes.len()
                || !(bytes[i + 4].is_ascii_alphanumeric() || bytes[i + 4] == b'-'))
        {
            out.push(doc[i..i + 4].to_string());
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

/// 「提案，未交付」节（标题行之后的部分）
fn proposals_section(doc: &str, heading: &str) -> (String, String) {
    let pos = doc
        .find(heading)
        .unwrap_or_else(|| panic!("功能矩阵缺「{heading}」提案节"));
    (doc[..pos].to_string(), doc[pos..].to_string())
}

/// 起真进程取 `rillanectl` 顶层命令面（同 cli_help_contract 纪律）
fn real_rillanectl_cmds() -> std::collections::BTreeSet<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_rillanectl"))
        .arg("--help")
        .output()
        .expect("起 rillanectl");
    let help = String::from_utf8(out.stdout).expect("help UTF-8");
    let mut names = std::collections::BTreeSet::new();
    if let Some(section) = help.split("Commands:\n").nth(1) {
        let section = section.split("\n\n").next().expect("Commands 段未闭合");
        for line in section.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

const EN_HEAD: &str = "## Proposals, not delivered";
const ZH_HEAD: &str = "## 提案，未交付";

/// 双语页 F-ID 行集恰等 + 唯一性 + 最低覆盖；链接与引用产物存在；
/// 提案家族只许在提案节；能力表声明引用的 Debug 命令面真实。
#[test]
fn feature_matrix_pages_pair_and_ground_in_artifacts() {
    let en = read_repo("docs/feature-matrix.md");
    let zh = read_repo("docs/zh/feature-matrix.md");

    // -- F-ID 配对：双语行集恰等、页内唯一、≥15 行 --
    for (lang, doc) in [("en", &en), ("zh", &zh)] {
        let ids = feature_ids(doc);
        assert!(
            ids.len() >= 15,
            "{lang} 页能力行不足 15 行（解析器失效兜底）"
        );
        let mut uniq = ids.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(
            ids.len(),
            uniq.len(),
            "{lang} 页 F-ID 重复：重复即行歧义——{ids:?}"
        );
    }
    let en_set: std::collections::BTreeSet<_> = feature_ids(&en).into_iter().collect();
    let zh_set: std::collections::BTreeSet<_> = feature_ids(&zh).into_iter().collect();
    let en_only: Vec<_> = en_set.difference(&zh_set).collect();
    let zh_only: Vec<_> = zh_set.difference(&en_set).collect();
    assert!(
        en_only.is_empty() && zh_only.is_empty(),
        "双语功能矩阵行集漂移：en 独有 {en_only:?}，zh 独有 {zh_only:?}——沉掉一行必须两语同沉"
    );

    // -- 交叉引用必须落在已定义行上（悬空 F-ID 即笔误）--
    for (lang, doc) in [("en", &en), ("zh", &zh)] {
        let rows: std::collections::BTreeSet<_> = feature_ids(doc).into_iter().collect();
        let tokens: std::collections::BTreeSet<_> = all_f_tokens(doc).into_iter().collect();
        let dangling: Vec<_> = tokens.difference(&rows).collect();
        assert!(
            dangling.is_empty(),
            "{lang} 页存在悬空 F-ID 引用 {dangling:?}——交叉引用必须指向已定义能力行"
        );
    }

    // -- 链接解析（相对各自文档目录）--
    for doc_path in ["docs/feature-matrix.md", "docs/zh/feature-matrix.md"] {
        let doc = read_repo(doc_path);
        let base_dir = PathBuf::from(doc_path).parent().unwrap().to_path_buf();
        let links = rel_links(&doc);
        assert!(
            !links.is_empty(),
            "{doc_path} 链接面不得为空（解析器失效兜底）"
        );
        for t in &links {
            let path = t.split('#').next().unwrap();
            let resolved = repo_root().join(&base_dir).join(path);
            assert!(
                resolved.exists(),
                "{doc_path} 链接目标不存在：{t}（解析为 {}）",
                resolved.display()
            );
        }
        // 引用产物（行内代码/散文形式）真实存在
        for artifact in [
            "contracts/build_matrix_v1.json",
            "contracts/desktop_e2e_matrix_v1.json",
            "contracts/parallel_scenario_matrix_v1.json",
            "contracts/mobile_diagnostic_bridge_v1.json",
            "apps/rillane-mcp/sdk-acceptance/EVIDENCE.md",
            "apps/rillane-mcp/sdk-acceptance/accept.cjs",
        ] {
            assert!(
                repo_root().join(artifact).exists(),
                "{doc_path} 引用产物不存在：{artifact}"
            );
        }
    }

    // -- 提案隔离：四个提案家族只许出现在提案节之后 --
    for (doc_path, doc, heading) in [
        ("docs/feature-matrix.md", &en, EN_HEAD),
        ("docs/zh/feature-matrix.md", &zh, ZH_HEAD),
    ] {
        let (head, tail) = proposals_section(doc, heading);
        let families = [
            ("v1 quality", "v1 质量"),
            ("public packet APIs", "公开 packet API"),
            ("device acceptance batches", "真机验收批次"),
            ("NaiveProxy (RIL-112)", "NaiveProxy（RIL-112）"),
        ];
        for (en_phrase, zh_phrase) in families {
            let phrase = if doc_path.ends_with("zh/feature-matrix.md") {
                zh_phrase
            } else {
                en_phrase
            };
            assert!(
                tail.contains(phrase),
                "{doc_path} 提案节缺已知提案家族「{phrase}」——提案家族清单不得单语缩水"
            );
            assert!(
                !head.contains(phrase),
                "{doc_path} 能力表混入提案措辞「{phrase}」——提案和已交付必须分开"
            );
        }
    }

    // -- 能力表声明的 Debug 命令面真实（F-10 行引用的四命令）--
    let real = real_rillanectl_cmds();
    assert!(real.len() > 20, "命令面解析失效兜底");
    for cmd in ["diagnose", "trace", "explain", "probe"] {
        assert!(
            real.contains(cmd),
            "功能矩阵 F-10 声明的命令不在二进制面：{cmd}"
        );
    }

    // -- 平台视图与证据索引互链在场（能力视图 ≠ 平台视图，双向可达）--
    for (doc_path, doc) in [
        ("docs/feature-matrix.md", &en),
        ("docs/zh/feature-matrix.md", &zh),
    ] {
        assert!(
            doc.contains("platform-support.md"),
            "{doc_path} 缺平台视图互链"
        );
        assert!(
            doc.contains("acceptance-evidence/README"),
            "{doc_path} 缺验收证据索引互链"
        );
    }
}

/// 自证：zh 页沉掉一行 F-ID → 本门以「行集漂移」点名失败。
#[test]
#[should_panic(expected = "双语功能矩阵行集漂移")]
fn comparator_bites_on_missing_zh_row() {
    let zh = read_repo("docs/zh/feature-matrix.md").replacen("| F-15 |", "| F-9x |", 1);
    let en = read_repo("docs/feature-matrix.md");
    let en_set: std::collections::BTreeSet<_> = feature_ids(&en).into_iter().collect();
    let zh_set: std::collections::BTreeSet<_> = feature_ids(&zh).into_iter().collect();
    let en_only: Vec<_> = en_set.difference(&zh_set).collect();
    let zh_only: Vec<_> = zh_set.difference(&en_set).collect();
    assert!(
        en_only.is_empty() && zh_only.is_empty(),
        "双语功能矩阵行集漂移：en 独有 {en_only:?}，zh 独有 {zh_only:?}——沉掉一行必须两语同沉"
    );
}

/// 自证：提案措辞混入能力表 → 本门以「混入提案措辞」点名失败。
#[test]
#[should_panic(expected = "能力表混入提案措辞")]
fn comparator_bites_on_proposal_leak_into_table() {
    let en =
        read_repo("docs/feature-matrix.md").replacen("| F-01 |", "| F-01 public packet APIs |", 1);
    let (head, _tail) = proposals_section(&en, EN_HEAD);
    assert!(
        !head.contains("public packet APIs"),
        "docs/feature-matrix.md 能力表混入提案措辞「public packet APIs」——提案和已交付必须分开"
    );
}
