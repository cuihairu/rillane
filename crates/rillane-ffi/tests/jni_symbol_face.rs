//! RIL-043 第一段：Android JNI 桥接符号面契约。
//!
//! Kotlin 宿主 `RillaneFfi` object（platforms/android/.../RillaneFfi.kt，
//! `external fun <name>`）与 Rust 侧 `jni_bridge.rs`（导出符号
//! `Java_com_rillane_rillane_RillaneFfi_<name>`）的**方法名集合恰等**——
//! 这是宿主桥接的链接契约：Rust 多导出 = Kotlin 面不可达的死符号；
//! Kotlin 多声明 = 加载期 `UnsatisfiedLinkError`（运行期炸，不是编译期）。
//! RIL-083 的 C 头门（contract_query_face.rs）显式把 JNI 面留给本门。
//!
//! 诚实边界：本门只钉符号面（静态可核验）；RIL-043 验收主项（fd 与公开
//! packetFlow 双向桥接、无悬空指针/取消后回调/无界队列）需真机批次，
//! 主勾选保持关闭。文本扫描与 contract_query_face 的头文件扫描同一纪律。

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// 从 Rust 源里扫 `Java_com_rillane_rillane_RillaneFfi_<name>(` 导出形态
/// （名字后紧跟 `(` 才算导出声明，注释里的提法不收——与头文件扫描同纪律）。
fn scan_rust_jni_exports(text: &str) -> BTreeSet<String> {
    let prefix = "Java_com_rillane_rillane_RillaneFfi_";
    let mut names = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find(prefix) {
        let start = i + pos + prefix.len();
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let name = &text[start..end];
        if text[end..].trim_start().starts_with('(') {
            names.insert(name.to_string());
        }
        i = end;
    }
    names
}

/// 从 Kotlin 源里扫 `external fun <name>(` 声明形态。
fn scan_kotlin_externals(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("external fun ") else {
            continue;
        };
        if let Some(name) = rest.split('(').next() {
            let name = name.trim();
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "Kotlin external fun 名字形态异常：{name:?}"
            );
            names.insert(name.to_string());
        }
    }
    names
}

fn load_side() -> (BTreeSet<String>, BTreeSet<String>) {
    let rust = std::fs::read_to_string(repo_root("crates/rillane-ffi/src/jni_bridge.rs"))
        .expect("读取 jni_bridge.rs");
    let kotlin = std::fs::read_to_string(repo_root(
        "platforms/android/app/src/main/java/com/rillane/rillane/RillaneFfi.kt",
    ))
    .expect("读取 RillaneFfi.kt");
    let exports = scan_rust_jni_exports(&rust);
    let externals = scan_kotlin_externals(&kotlin);
    assert!(
        !exports.is_empty() && !externals.is_empty(),
        "两侧都应扫到符号（扫描器自身失效）"
    );
    (exports, externals)
}

#[test]
fn kotlin_face_matches_jni_exports() {
    let (exports, externals) = load_side();
    let export_only: Vec<&String> = exports.difference(&externals).collect();
    let kotlin_only: Vec<&String> = externals.difference(&exports).collect();
    assert!(
        export_only.is_empty(),
        "JNI 导出面多出 {export_only:?}（Kotlin 桥不可达的死符号——补 Kotlin 声明或删导出）"
    );
    assert!(
        kotlin_only.is_empty(),
        "Kotlin 面多声明 {kotlin_only:?}（加载期 UnsatisfiedLinkError——补 Rust 导出或删声明）"
    );
    // 已知桥接面形状：15 个方法（4 生命周期/状态 + 8 查询 + 2 TUN fd 面
    // + 1 秘密引用启动——RIL-044 第二段显式过门）。
    assert_eq!(externals.len(), 15, "桥接面方法数变化须显式过本门");
    for must in [
        "version",
        "lastError",
        "start",
        "startWithSecrets",
        "stop",
        "isRunning",
        "statsJson",
        "routingJson",
        "nodesJson",
        "dnsStatsJson",
        "dnsResolversJson",
        "flowsJson",
        "flowJson",
        "tunStart",
        "tunStop",
    ] {
        assert!(
            externals.contains(must),
            "桥接面缺已知方法 {must}（减面=破坏宿主，须同步 Kotlin 与 jni_bridge）"
        );
    }
}

/// 对账器自证：Kotlin 面多声明一个方法 → 本门以「Kotlin 面多声明」点名失败。
#[test]
#[should_panic(expected = "Kotlin 面多声明 [\"phantomCall\"]")]
fn comparator_bites_on_kotlin_drift() {
    let (exports, externals) = load_side();
    let mut externals = externals;
    externals.insert("phantomCall".to_string());
    let kotlin_only: Vec<&String> = externals.difference(&exports).collect();
    assert!(
        kotlin_only.is_empty(),
        "Kotlin 面多声明 {kotlin_only:?}（加载期 UnsatisfiedLinkError——补 Rust 导出或删声明）"
    );
}

/// 对账器自证：Rust 面多导出一个符号 → 本门以「死符号」点名失败。
#[test]
#[should_panic(expected = "Kotlin 桥不可达的死符号")]
fn comparator_bites_on_rust_drift() {
    let (exports, externals) = load_side();
    let mut exports = exports;
    exports.insert("phantomExport".to_string());
    let export_only: Vec<&String> = exports.difference(&externals).collect();
    assert!(
        export_only.is_empty(),
        "JNI 导出面多出 {export_only:?}（Kotlin 桥不可达的死符号——补 Kotlin 声明或删导出）"
    );
}
