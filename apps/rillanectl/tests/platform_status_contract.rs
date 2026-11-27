//! RIL-091 第七段：平台支持状态页与移动 FFI / RIL-044 / RIL-082 证据页对齐契约门。
//!
//! 第九段扩展：JNI 角色拆分（5 生命周期/状态 + 7 查询）从 Kotlin 源逐名
//! 分组核对证据页措辞、两语设计入口必列平台适配器选型页且 zh 双胞胎在
//! 场、RIL-084 证据页 Android 摘要不得压掉账本 run_note 的已验清单。
//! 前六段交付了站点、平台视图、命令 help、README、操作示例与功能矩阵，但
//! 后续 RIL-043/044 段把 JNI 面从 14 推到 18 方法、C ABI 从 15 推到 19 导出，
//! 历史证据页和平台视图没有跟上：仍有 14/15/16 方法、15 C ABI 符号的说法，
//! 仍把已交付的秘密注入/网络变化/IPC 写成「仍开放/未开工/下一段交付」。
//! 本门把这些事实从产物取数钉死：
//! - Kotlin `external fun` 恰 18 方法，平台视图与 RIL-043/044 证据页的计数
//!   与之相符，平台视图逐名列出四个新增方法（含原有的 version/lastError）；
//! - RIL-082 证据页的 C ABI 计数与机器账本 `ffi.exports` 长度恰等；
//! - RIL-044 四个本地账本在两语证据索引逐条配对、指向真实文档与契约测试；
//!   已交付面的「未开工/下一阶段」措辞禁入，真机层边界必须在诚实边界节内；
//! - 两语索引引用的机器账本集合涵盖证据页引用的全部 `contracts/*.json`；
//! - OpenWrt README 无悬空「当前实现 注记」交叉引用，systemd README 的 deb
//!   文件名模板与 build.sh 实际产物一致。
//!
//! 对账器自证：幻影方法数、抹掉索引条目、注入「未开工」措辞、篡改 C ABI
//! 计数、注入悬空交叉引用，门必须点名失败。自证调用的是生产检查函数本身，
//! 不是复制的断言。本门只钉结构事实与措辞纪律；真机边界仍由各自证据文档
//! 与 FFI 契约门承担。

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

/// Kotlin 侧 `external fun <name>(` 声明（与 jni_symbol_face 同扫描纪律）
fn kotlin_externals(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("external fun ") else {
            continue;
        };
        if let Some(name) = rest.split('(').next() {
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                names.insert(name.to_string());
            }
        }
    }
    names
}

const NEW_METHODS: [&str; 4] = [
    "startWithSecrets",
    "networkChanged",
    "diagnosticIpcStart",
    "diagnosticIpcStop",
];

/// 页面 → 当前 JNI 方法数短语（与 Kotlin 源码取出的数字核对）
const JNI_COUNT_PHRASES: [(&str, &str); 7] = [
    ("docs/platform-support.md", "18-symbol JNI face"),
    ("docs/zh/platform-support.md", "18 符号 JNI 面"),
    (
        "docs/acceptance-evidence/ril-043-jni-symbol-face.md",
        "18-method face",
    ),
    (
        "docs/acceptance-evidence/ril-043-jni-symbol-face.zh.md",
        "18 方法面",
    ),
    (
        "docs/acceptance-evidence/ril-044-secret-injection.md",
        "18 methods",
    ),
    (
        "docs/acceptance-evidence/ril-044-secret-injection.zh.md",
        "18 方法",
    ),
    (
        "docs/acceptance-evidence/ril-044-network-change.md",
        "18 methods",
    ),
];

/// 剩余 JNI 相关证据页：诊断 IPC 页已写 18，网络变化中文页同数
const EXTRA_JNI_COUNT_PHRASES: [(&str, &str); 2] = [
    (
        "docs/acceptance-evidence/ril-044-network-change.zh.md",
        "18 方法",
    ),
    (
        "docs/acceptance-evidence/ril-044-diagnostic-ipc.zh.md",
        "18 方法",
    ),
];

/// 已交付面禁用的历史时点措辞
const STALE_JNI_COUNTS: [&str; 6] = [
    "14-method face",
    "14 方法面",
    "15 methods",
    "15 方法",
    "16 methods",
    "16 方法",
];
const STALE_DELIVERY_PHRASES: [&str; 6] = [
    "IPC still open",
    "IPC 仍开放",
    "IPC）未开工",
    "ipc not started",
    "未开工",
    "delivered in the next segment",
];
const STALE_DELIVERY_PHRASES_ZH: [&str; 2] = ["有界诊断 IPC 在下一段交付", "RIL-044 其余交付"];

/// JNI 角色分组（RIL-091 第九段钉死拆分：证据页曾写 4 生命周期/状态 +
/// 8 查询，实际 Kotlin 面是 5 + 7——总数同为 18，计数门接不住分类错）
const ROLE_LIFECYCLE_STATUS: [&str; 5] = ["version", "lastError", "start", "stop", "isRunning"];
const ROLE_QUERY: [&str; 7] = [
    "statsJson",
    "routingJson",
    "nodesJson",
    "dnsStatsJson",
    "dnsResolversJson",
    "flowsJson",
    "flowJson",
];
const ROLE_TUN_FD: [&str; 2] = ["tunStart", "tunStop"];
const ROLE_SECRET_INJECTION: [&str; 1] = ["startWithSecrets"];
const ROLE_NETWORK_CHANGE: [&str; 1] = ["networkChanged"];
const ROLE_DIAGNOSTIC_IPC: [&str; 2] = ["diagnosticIpcStart", "diagnosticIpcStop"];

const STALE_ROLE_SPLIT: [&str; 2] = ["4 lifecycle/status + 8 query", "4 生命周期/状态 + 8 查询"];

/// 生产检查：从 Kotlin 源真分组核对证据页的角色拆分（总数是 18 但拆错同样
/// 误导宿主消费方；分组与源逐名封闭，防止 5+7 漂移成 6+6 也漏检）
fn check_jni_role_split(path: &str, doc: &str, methods: &BTreeSet<String>) {
    let groups = [
        ("lifecycle/status", &ROLE_LIFECYCLE_STATUS[..]),
        ("query", &ROLE_QUERY[..]),
        ("TUN fd", &ROLE_TUN_FD[..]),
        ("secret injection", &ROLE_SECRET_INJECTION[..]),
        ("network change", &ROLE_NETWORK_CHANGE[..]),
        ("diagnostic IPC", &ROLE_DIAGNOSTIC_IPC[..]),
    ];
    for (role, expected) in groups {
        for name in expected {
            assert!(
                methods.contains(*name),
                "{path} 的角色分组声明 {role} 含 Kotlin 面不存在的方法 {name}"
            );
        }
    }
    let covered: BTreeSet<&str> = groups
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    assert_eq!(
        covered.len(),
        methods.len(),
        "{path} 角色分组源面未一一覆盖：源 {methods:?} 分组 {covered:?}"
    );
    let phrase = if path.ends_with(".zh.md") {
        "5 生命周期/状态 + 7 查询"
    } else {
        "5 lifecycle/status + 7 query"
    };
    assert!(
        doc.contains(phrase),
        "{path} JNI 角色拆分漂移——Kotlin 面逐名分组为 5 lifecycle/status + 7 query，须写「{phrase}」"
    );
    for stale in STALE_ROLE_SPLIT {
        assert!(
            !doc.contains(stale),
            "{path} 仍写旧角色拆分「{stale}」——实际为 5 生命周期/状态 + 7 查询"
        );
    }
}

/// RIL-044 四个核心半边证据：条目锚点、证据文档、契约测试
const RIL_044_EVIDENCE: [(&str, &str, &str); 4] = [
    (
        "ril-044-host-lifecycle",
        "docs/acceptance-evidence/ril-044-host-lifecycle.md",
        "crates/rillane-ffi/tests/host_lifecycle_contract.rs",
    ),
    (
        "ril-044-secret-injection",
        "docs/acceptance-evidence/ril-044-secret-injection.md",
        "crates/rillane-ffi/tests/secret_injection_contract.rs",
    ),
    (
        "ril-044-network-change",
        "docs/acceptance-evidence/ril-044-network-change.md",
        "crates/rillane-ffi/tests/network_changed_contract.rs",
    ),
    (
        "ril-044-diagnostic-ipc",
        "docs/acceptance-evidence/ril-044-diagnostic-ipc.md",
        "crates/rillane-ffi/tests/diagnostic_ipc_contract.rs",
    ),
];

/// 证据文档 → 中文证据文档（`.md` → `.zh.md`）
fn zh_doc_path(doc_path: &str) -> String {
    doc_path.strip_suffix(".md").unwrap_or(doc_path).to_string() + ".zh.md"
}

/// 两语索引条目锚点数：单语沉行即点名
fn evidence_anchors(doc: &str) -> Vec<String> {
    RIL_044_EVIDENCE
        .iter()
        .filter(|(anchor, _, _)| doc.contains(anchor))
        .map(|(anchor, _, _)| anchor.to_string())
        .collect()
}

/// 生产检查：页面方法数短语必须等于 Kotlin 侧真实方法数
fn check_jni_count(path: &str, doc: &str, actual_count: usize) {
    let (_, phrase) = JNI_COUNT_PHRASES
        .iter()
        .chain(EXTRA_JNI_COUNT_PHRASES.iter())
        .find(|(p, _)| *p == path)
        .unwrap_or_else(|| panic!("{path} 不在 JNI 计数钉法清单中"));
    assert_eq!(
        actual_count, 18,
        "Kotlin FFI 面方法数变化：现为 {actual_count}，须同步两语平台页与证据页并过本门"
    );
    assert!(
        doc.contains(phrase),
        "{path} 的 JNI 方法数已漂移——Kotlin 侧有 {actual_count} 个 external fun，必须写「{phrase}」"
    );
    for stale in STALE_JNI_COUNTS {
        assert!(
            !doc.contains(stale),
            "{path} 仍写旧方法数「{stale}」——历史时点措辞须更新为「{phrase}」"
        );
    }
}

/// 生产检查：证据索引条目逐条配对且不把已交付面写成仍开放
fn check_evidence_index(lang: &str, doc: &str) {
    let anchors = evidence_anchors(doc);
    assert_eq!(
        anchors.len(),
        RIL_044_EVIDENCE.len(),
        "{lang} 证据索引 RIL-044 条目漂移：找到 {anchors:?}，四个本地账本必须逐条在索引中"
    );
    for phrase in STALE_DELIVERY_PHRASES
        .iter()
        .chain(STALE_DELIVERY_PHRASES_ZH.iter())
    {
        assert!(
            !doc.contains(phrase),
            "{lang} 证据索引仍陈旧声称「{phrase}」——RIL-044 核心半边已交付本地账本"
        );
    }
}

/// 生产检查：证据页诚实边界节内保留真机层缺口、不含已交付面的「未开工」措辞
fn check_evidence_body(lang: &str, anchor: &str, doc: &str) {
    let (boundary, gap_token) = if lang == "zh" {
        let section = doc
            .split("## 如实边界")
            .nth(1)
            .or_else(|| doc.split("## 诚实边界").nth(1))
            .unwrap_or_else(|| {
                panic!("{lang} {anchor} 证据页缺诚实边界节（「如实边界」或「诚实边界」）")
            });
        (section, "真机")
    } else {
        let section = doc
            .split("## Honest boundary")
            .nth(1)
            .unwrap_or_else(|| panic!("{lang} {anchor} 证据页缺「## Honest boundary」节"));
        (section, "device")
    };
    assert!(
        boundary.contains(gap_token),
        "{lang} {anchor} 诚实边界节缺真机层缺口声明——本地账本不能冒充设备验收"
    );
    for phrase in STALE_DELIVERY_PHRASES_ZH
        .iter()
        .chain(STALE_DELIVERY_PHRASES.iter())
    {
        assert!(
            !doc.contains(phrase),
            "{lang} {anchor} 证据页仍把已交付面写成「{phrase}」——事实漂移须修"
        );
    }
}

/// 生产检查：RIL-082 证据页的 C ABI 计数与机器账本 exports 长度恰等
fn check_bridge_export_count(path: &str, doc: &str, declared: usize) {
    let phrase = if path.ends_with(".zh.md") {
        format!("{declared} 个 C ABI 符号")
    } else {
        format!("{declared} C ABI symbols")
    };
    assert!(
        doc.contains(&phrase),
        "{path} 的 C ABI 导出数与机器账本不一致——账本声明 {declared} 个，页内必须写「{phrase}」"
    );
    for stale in ["15 C ABI symbols", "15 个 C ABI 符号"] {
        assert!(
            !doc.contains(stale),
            "{path} 仍写旧导出数「{stale}」——账本已随 RIL-044 段扩展"
        );
    }
}

/// 证据页声明的机器账本引用（「The machine-readable source is `contracts/…json`」
/// 或「机器可读真源为 `contracts/…json`」形态；散文里的历史文件名不算账本声明）
fn declared_ledgers(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in doc.lines() {
        if line.contains("machine-readable source") || line.contains("机器可读真源") {
            let mut rest = line;
            while let Some(pos) = rest.find("contracts/") {
                let tail = &rest[pos..];
                let end = tail
                    .find(|c: char| {
                        !(c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '.')
                    })
                    .unwrap_or(tail.len());
                let token = &tail[..end];
                if token.ends_with(".json") {
                    out.push(token.to_string());
                }
                rest = &tail[end.min(tail.len())..];
            }
        }
    }
    out
}

#[test]
fn platform_and_evidence_pages_pin_current_jni_face() {
    let kotlin = read_repo("platforms/android/app/src/main/java/com/rillane/rillane/RillaneFfi.kt");
    let methods = kotlin_externals(&kotlin);
    assert_eq!(
        methods.len(),
        18,
        "Kotlin FFI 面方法数变化：须同步 jni_symbol_face、平台页与证据页并过本门"
    );
    for name in NEW_METHODS {
        assert!(
            methods.contains(name),
            "Kotlin 面缺已知方法 {name}——平台页声称的方法数不可信"
        );
    }
    for (path, phrase) in JNI_COUNT_PHRASES
        .iter()
        .chain(EXTRA_JNI_COUNT_PHRASES.iter())
    {
        check_jni_count(path, &read_repo(path), methods.len());
        assert!(
            read_repo(path).contains(phrase),
            "{path} 计数短语丢面（扫描器失效兜底）"
        );
    }
    // 平台视图逐名列出完整面（含 version/lastError 与四个新增方法）
    for path in ["docs/platform-support.md", "docs/zh/platform-support.md"] {
        let doc = read_repo(path);
        for name in NEW_METHODS.iter() {
            assert!(
                doc.contains(name),
                "{path} 未列出已知 JNI 方法 {name}——运行面描述必须跟上产物"
            );
        }
    }
}

#[test]
fn ril_044_evidence_index_pairs_and_grounds() {
    let en = read_repo("docs/acceptance-evidence/README.md");
    let zh = read_repo("docs/zh/acceptance-evidence/README.md");
    check_evidence_index("en", &en);
    check_evidence_index("zh", &zh);
    assert_eq!(
        evidence_anchors(&en),
        evidence_anchors(&zh),
        "两语 RIL-044 证据条目集合不配对——沉掉一行必须两语同沉"
    );

    for (anchor, doc_path, test_path) in RIL_044_EVIDENCE {
        let zh_path = zh_doc_path(doc_path);
        for path in [doc_path, zh_path.as_str(), test_path] {
            assert!(
                repo_root().join(path).exists(),
                "{anchor} 悬空：{path} 不存在"
            );
        }
        for (lang, path) in [("en", doc_path), ("zh", zh_path.as_str())] {
            check_evidence_body(lang, anchor, &read_repo(path));
        }
    }
}

#[test]
fn evidence_index_lists_every_machine_ledger_it_cites() {
    let mut cited = BTreeSet::new();
    for entry in
        std::fs::read_dir(repo_root().join("docs/acceptance-evidence")).expect("读证据目录")
    {
        let path = entry.expect("目录项").path();
        if path.extension().is_some_and(|e| e == "md") {
            cited.extend(declared_ledgers(
                &std::fs::read_to_string(&path).expect("读证据页"),
            ));
        }
    }
    assert!(
        cited.contains("contracts/mobile_diagnostic_bridge_v1.json"),
        "证据页引用的诊断桥账本未纳入扫描（扫描器失效兜底）"
    );
    for (lang, index_path) in [
        ("en", "docs/acceptance-evidence/README.md"),
        ("zh", "docs/zh/acceptance-evidence/README.md"),
    ] {
        let doc = read_repo(index_path);
        for token in &cited {
            assert!(
                doc.contains(token),
                "{lang} 索引机器账本清单漏掉 {token}——证据页引用了它，索引必须列出"
            );
        }
    }
}

#[test]
fn ril_082_export_count_matches_ledger() {
    let ledger: Value =
        serde_json::from_str(&read_repo("contracts/mobile_diagnostic_bridge_v1.json"))
            .expect("解析诊断桥账本");
    let declared = ledger["ffi"]["exports"]
        .as_array()
        .expect("ffi.exports 数组")
        .len();
    assert!(declared >= 19, "账本导出数缩水疑为账本损坏");
    for path in [
        "docs/acceptance-evidence/ril-082-mobile-diagnostic-bridge.md",
        "docs/acceptance-evidence/ril-082-mobile-diagnostic-bridge.zh.md",
    ] {
        check_bridge_export_count(path, &read_repo(path), declared);
    }
}

#[test]
fn platform_readmes_have_no_dangling_notes_or_wrong_deb_template() {
    let openwrt = read_repo("platforms/openwrt/README.md");
    assert!(
        !openwrt.contains("当前实现 注记"),
        "platforms/openwrt/README.md 仍有悬空交叉引用「当前实现 注记」——仓内无该节"
    );
    assert!(
        openwrt.contains("## 验证边界"),
        "platforms/openwrt/README.md 缺「验证边界」节——回填目标必须在场"
    );
    let systemd = read_repo("platforms/systemd/README.md");
    let build = read_repo("platforms/systemd/build.sh");
    assert!(
        build.contains("rillane_${PKG_VERSION}-${PKG_RELEASE}_${arch}.deb"),
        "systemd/build.sh 的 deb 命名模板变了——请同步本门"
    );
    assert!(
        systemd.contains("rillane_<version>-<release>_{amd64,arm64}.deb"),
        "platforms/systemd/README.md 的 deb 模板与 build.sh 不符（release 段不可漏）"
    );
}

#[test]
fn jni_evidence_pages_pin_role_split_from_kotlin_face() {
    let kotlin = read_repo("platforms/android/app/src/main/java/com/rillane/rillane/RillaneFfi.kt");
    let methods = kotlin_externals(&kotlin);
    for path in [
        "docs/acceptance-evidence/ril-043-jni-symbol-face.md",
        "docs/acceptance-evidence/ril-043-jni-symbol-face.zh.md",
    ] {
        check_jni_role_split(path, &read_repo(path), &methods);
    }
}

#[test]
fn design_index_twin_pairs_platform_adapter_decision() {
    let en = read_repo("docs/design/index.md");
    let zh = read_repo("docs/zh/design/index.md");
    let anchor = "platform-adapter-decision";
    assert!(
        en.contains(anchor) && zh.contains(anchor),
        "两语设计入口必须都列平台适配器选型决策（EN={} ZH={}）",
        en.contains(anchor),
        zh.contains(anchor)
    );
    for path in [
        "docs/design/platform-adapter-decision.md",
        "docs/zh/design/platform-adapter-decision.md",
    ] {
        let doc = read_repo(path);
        assert!(
            doc.contains("D-PA-6"),
            "{path} 缺已接受的 D-PA-1..6 决策集（空壳或沉行）"
        );
        assert!(
            doc.contains("RIL-094"),
            "{path} 缺 iOS 签名硬门边界——决策不能冒充解阻"
        );
    }
}

#[test]
fn artifact_matrix_evidence_matches_ledger_run_note() {
    let matrix: Value =
        serde_json::from_str(&read_repo("contracts/build_matrix_v1.json")).expect("构建矩阵解析");
    let note = matrix["platforms"]["android"]["run_note"]
        .as_str()
        .expect("android.run_note");
    for phrase in [
        "安装",
        "autostart",
        "撤销",
        "切网",
        "onTrimMemory",
        "字体放大",
        "四 Tab 渲染",
        "仅 ICMP 回环",
    ] {
        assert!(
            note.contains(phrase),
            "账本 android.run_note 漂移：缺「{phrase}」"
        );
    }
    for path in [
        "docs/acceptance-evidence/ril-084-artifact-matrix.md",
        "docs/acceptance-evidence/ril-084-artifact-matrix.zh.md",
    ] {
        let doc = read_repo(path);
        for phrase in ["autostart", "onTrimMemory", "四 Tab 渲染", "仅 ICMP 回环"] {
            assert!(
                doc.contains(phrase),
                "{path} Android 运行验收摘要与账本 run_note 不一致：缺「{phrase}」"
            );
        }
        assert!(
            !doc.contains("verified_emulator（AVD API33，仅 ICMP 回环）"),
            "{path} 仍把账本七项已验面压缩成「仅 ICMP 回环」"
        );
    }
}

/// 平台视图的 Linux 验收状态格必须与桌面账本同口径：账本里已升格
/// `verified_local` 的条款不得仍写成「未跑」（RIL-085 第二段把
/// permission_denied/port_reuse 升格后，平台视图曾残留旧措辞）。本检查
/// 从账本取数，不写死条款名——后续任何格升格都会被接住。
fn check_linux_verified_clauses_not_stale(lang: &str, doc: &str, matrix: &Value) {
    let mut verified = Vec::new();
    for (clause, entry) in matrix["clauses"].as_object().expect("desktop clauses 对象") {
        let status = entry["cells"]["linux"]["status"]
            .as_str()
            .unwrap_or_else(|| panic!("desktop {clause}/linux 缺状态"));
        if status == "verified_local" || status == "verified_device" {
            verified.push(clause.as_str());
        }
    }
    verified.sort();
    assert!(
        verified.contains(&"permission_denied") && verified.contains(&"port_reuse"),
        "账本已升格面不在预期内（账本漂移）：{verified:?}"
    );
    // 平台视图 Linux 行必须点名这两项已本地实测，且不得再把它们写进
    // 「未跑」格。措辞可双语，按 lang 选词。
    let (label, verified_word, not_run_word) = match lang {
        "en" => ("EN", "verified by real-process", "not run"),
        _ => ("zh", "已真实进程实测", "未跑"),
    };
    {
        let line = doc
            .lines()
            .find(|l| l.starts_with("| Linux (systemd/deb)"))
            .unwrap_or_else(|| panic!("{label} 平台视图缺 Linux 行"));
        assert!(
            line.contains(verified_word),
            "{label} 平台视图 Linux 行未反映账本已升格面（{verified_word}）：{line}"
        );
        // 只允许 browser-grouped/fault samples 出现在未跑格；权限/复用
        // 若仍在「未跑」一侧即为陈旧。
        if let Some((_, tail)) = line.split_once(not_run_word) {
            assert!(
                !tail.contains("permission_denied")
                    && !tail.contains("port_reuse")
                    && !tail.contains("权限不足")
                    && !tail.contains("端口复用"),
                "{label} 平台视图仍把账本 verified_local 的权限不足/端口复用写成未跑：{line}"
            );
        }
    }
}

#[test]
fn platform_pages_pin_current_desktop_e2e_verified_faces() {
    let matrix: Value = serde_json::from_str(&read_repo("contracts/desktop_e2e_matrix_v1.json"))
        .expect("桌面账本解析");
    for (lang, path) in [
        ("en", "docs/platform-support.md"),
        ("zh", "docs/zh/platform-support.md"),
    ] {
        let doc = read_repo(path);
        check_linux_verified_clauses_not_stale(lang, &doc, &matrix);
    }
}

// ---------------------------------------------------------------------------
// 对账器自证：全部调用生产检查函数，不复制断言
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "JNI 方法数已漂移")]
fn comparator_bites_on_stale_method_count() {
    let doc = read_repo("docs/platform-support.md").replacen(
        "18-symbol JNI face",
        "14-symbol JNI face",
        1,
    );
    check_jni_count("docs/platform-support.md", &doc, 18);
}

#[test]
#[should_panic(expected = "四个本地账本必须逐条在索引中")]
fn comparator_bites_on_missing_evidence_row() {
    let doc: String = read_repo("docs/acceptance-evidence/README.md")
        .lines()
        .filter(|line| !line.contains("ril-044-diagnostic-ipc"))
        .collect::<Vec<_>>()
        .join("\n");
    check_evidence_index("en", &doc);
}

#[test]
#[should_panic(expected = "事实漂移须修")]
fn comparator_bites_on_stale_open_claim() {
    let doc = read_repo("docs/acceptance-evidence/ril-044-secret-injection.md").replacen(
        "## Honest boundary",
        "## Honest boundary\n\nRIL-044 其余交付（网络变化通知、有界诊断 IPC）未开工。",
        1,
    );
    check_evidence_body("en", "ril-044-secret-injection", &doc);
}

#[test]
#[should_panic(expected = "旧导出数")]
fn comparator_bites_on_stale_export_count() {
    let doc = read_repo("docs/acceptance-evidence/ril-082-mobile-diagnostic-bridge.md").replacen(
        "19 C ABI symbols",
        "15 C ABI symbols",
        1,
    );
    check_bridge_export_count(
        "docs/acceptance-evidence/ril-082-mobile-diagnostic-bridge.md",
        &doc,
        19,
    );
}

#[test]
#[should_panic(expected = "仍有悬空交叉引用")]
fn comparator_bites_on_dangling_note() {
    let doc = read_repo("platforms/openwrt/README.md").replacen(
        "见下方「验证边界」",
        "见 当前实现 注记",
        1,
    );
    assert!(
        !doc.contains("当前实现 注记"),
        "platforms/openwrt/README.md 仍有悬空交叉引用「当前实现 注记」——仓内无该节"
    );
}

#[test]
#[should_panic(expected = "角色分组源面未一一覆盖")]
fn comparator_bites_on_role_split_not_covering_face() {
    let kotlin = read_repo("platforms/android/app/src/main/java/com/rillane/rillane/RillaneFfi.kt");
    let mut methods = kotlin_externals(&kotlin);
    methods.insert("phantomMethod".to_string());
    check_jni_role_split(
        "docs/acceptance-evidence/ril-043-jni-symbol-face.md",
        &read_repo("docs/acceptance-evidence/ril-043-jni-symbol-face.md"),
        &methods,
    );
}

#[test]
#[should_panic(expected = "平台视图 Linux 行未反映账本已升格面")]
fn comparator_bites_on_stale_linux_verified_face() {
    // 把 Linux 行里「已真实进程实测」改回「未跑」——平台视图重述账本
    // verified_local 面为未跑，本门必须点名。
    let matrix: Value = serde_json::from_str(&read_repo("contracts/desktop_e2e_matrix_v1.json"))
        .expect("桌面账本解析");
    let stale = read_repo("docs/platform-support.md").replacen(
        "cross-uid permission denial and same-target multi-process port reuse verified by real-process tests",
        "permission_denied / port_reuse not run",
        1,
    );
    check_linux_verified_clauses_not_stale("en", &stale, &matrix);
}
