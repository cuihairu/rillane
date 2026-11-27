//! RIL-091 第八段：协议表双语行集合与诊断开销页的时点漂移契约门。
//!
//! 上一段钉了平台视图 / FFI / RIL-044 证据页，但两处仍可本地核验的漂移
//! 逃过所有既有门：① 中文 PROTOCOLS 出站表漏了 MASQUE 行（英文有、RIL-120
//! 已交付且两语 protocol-backends.md 都写了），Vitepress 只查链接不查语义；
//! ② 两语 diagnostics-overhead 仍写「trace 准入没有生产调用点 / 接线后复测」，
//! 与 RIL-083 已交付的 `TracedFlowOutput` 生产接线及活面证据矛盾。
//! 本门从产物取数钉死：
//! - 两语 PROTOCOLS 出站表的行名集合与相对顺序一致——双语表是同一契约的两
//!   种语言，一边沉一行（如 MASQUE）即点名；
//! - 两语开销页不得含旧「未接线/没有生产调用点/接线后复测」措辞，
//!   必须出现生产锚点名与具名的端到端缺口声明。
//!
//! 本门只钉结构与措辞事实；协议连接器自身的验收由各自契约门承担。

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

/// 出站表行名：跳过表头与分隔行，归一两语不同写法的规范名
fn outbound_rows(doc: &str) -> Vec<String> {
    let start = doc
        .find("## Outbounds")
        .or_else(|| doc.find("## 出站"))
        .unwrap_or_else(|| panic!("协议页缺出站节（## Outbounds / ## 出站）"));
    let rest = &doc[start..];
    let end = rest[3..].find("\n## ").map(|p| p + 3).unwrap_or(rest.len());
    let mut names = Vec::new();
    for line in rest[..end].lines() {
        if !line.starts_with('|') {
            continue;
        }
        let Some(name) = line.split('|').nth(1).map(str::trim) else {
            continue;
        };
        if name.is_empty()
            || name == "---"
            || name == "Type"
            || name == "类型"
            || name.starts_with("Others")
            || name.starts_with("其他")
        {
            continue;
        }
        // 两语对 Hysteria v1 的括注写法不同；归一后再比
        let name = if name.starts_with("Hysteria（v1）") || name.starts_with("Hysteria (v1)") {
            "Hysteria v1"
        } else {
            name
        };
        names.push(name.to_string());
    }
    names
}

const STALE_WIRING_PHRASES: [&str; 6] = [
    "not wired to the collector",
    "no production call site",
    "Re-measure after the data-path wiring lands",
    "尚未接线到采集器",
    "没有生产调用点",
    "数据路径接线落地后复测",
];

/// 生产检查：两语出站表行集合与顺序必须配对
fn check_bilingual_rows(en_doc: &str, zh_doc: &str) {
    let en = outbound_rows(en_doc);
    let zh = outbound_rows(zh_doc);
    assert_eq!(
        en, zh,
        "PROTOCOLS 两语出站表行集合/顺序不配对：EN={en:?} ZH={zh:?}"
    );
    assert!(en.len() >= 18, "出站表行数缩水疑为整表丢失");
    assert!(
        en.contains(&"MASQUE".to_string()) && zh.contains(&"MASQUE".to_string()),
        "两语出站表必须列 MASQUE（RIL-120 已交付；英文有而中文沉行即为漂移）"
    );
}

/// 生产检查：开销页不含旧「未接线」时点措辞，且保留生产锚点与具名缺口
fn check_overhead_scope(lang: &str, doc: &str) {
    for phrase in STALE_WIRING_PHRASES {
        assert!(
            !doc.contains(phrase),
            "{lang} diagnostics-overhead 仍写旧时点措辞「{phrase}」——RIL-083 生产接线已落地"
        );
    }
    assert!(
        doc.contains("TracedFlowOutput"),
        "{lang} diagnostics-overhead 缺生产接线锚点 TracedFlowOutput"
    );
    let gap = if lang == "zh" {
        "具名缺口"
    } else {
        "named gap"
    };
    assert!(
        doc.contains(gap),
        "{lang} diagnostics-overhead 缺具名的端到端量测缺口声明"
    );
}

#[test]
fn protocol_tables_are_bilingual_and_pin_masque() {
    let en = read_repo("docs/PROTOCOLS.md");
    let zh = read_repo("docs/zh/PROTOCOLS.md");
    check_bilingual_rows(&en, &zh);
}

#[test]
fn overhead_pages_pin_production_wiring_without_claiming_e2e_numbers() {
    check_overhead_scope("en", &read_repo("docs/diagnostics-overhead.md"));
    check_overhead_scope("zh", &read_repo("docs/zh/diagnostics-overhead.md"));
}

// 自证：全部调用生产检查函数本身，不复制断言

#[test]
#[should_panic(expected = "两语出站表行集合/顺序不配对")]
fn comparator_bites_on_missing_zh_row() {
    let en = read_repo("docs/PROTOCOLS.md");
    let zh = read_repo("docs/zh/PROTOCOLS.md");
    let zh_dropped: String = zh
        .lines()
        .filter(|line| !line.starts_with("| MASQUE |"))
        .collect::<Vec<_>>()
        .join("\n");
    check_bilingual_rows(&en, &zh_dropped);
}

#[test]
#[should_panic(expected = "仍写旧时点措辞")]
fn comparator_bites_on_stale_wiring_claim() {
    let doc = read_repo("docs/diagnostics-overhead.md").replacen(
        "**Honest scope:** production trace admission exists",
        "**Honest scope:** the session data path is not wired to the collector yet",
        1,
    );
    check_overhead_scope("en", &doc);
}
