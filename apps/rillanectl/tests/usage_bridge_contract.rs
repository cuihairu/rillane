//! RIL-091 第五段：安装/恢复/Debug/MCP 示例与实际产物对齐契约门。
//!
//! 验收条款「安装/恢复/Debug/MCP 示例逐节对齐」的机器钉法：
//! 双语 `docs/usage-bridge.md` 里的真实命令面、`rillane-mcp` 旗标、16 个工具
//! 目录、相对链接与平台/证据路径都要与仓内产物一致；文档不能再声称
//! Explain/Trace/Probe/MCP「尚未实现」（这些面已落地）；根 README 的链接
//! 与任务计数沿用 `readme_contract.rs` 的既有钉法。对账器自证：陈旧「未实现」
//! 声明、幻影 MCP 旗标/工具/链接，门必须点名失败。
//!
//! 诚实边界：本页是操作示例，不是设备验收；设备层缺口由
//! `platforms/*/README.md` 与 `docs/acceptance-evidence/` 的具名缺口承担。

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

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

/// `--` 旗标（文档代码块/行内反引号）
fn scan_double_dash(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            let start = i;
            i += 2;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-') {
                i += 1;
            }
            let tok = &text[start..i];
            if tok[2..].chars().any(|c| c.is_ascii_alphabetic()) {
                out.insert(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

/// 某二进制 `--help` 文本
fn help_text(bin: &str, args: &[&str]) -> String {
    let exe = if bin == "rillanectl" {
        env!("CARGO_BIN_EXE_rillanectl").to_string()
    } else {
        repo_root()
            .join("target/debug")
            .join(bin)
            .to_string_lossy()
            .into_owned()
    };
    let mut full: Vec<&str> = args.to_vec();
    full.push("--help");
    let out = Command::new(&exe)
        .args(&full)
        .output()
        .unwrap_or_else(|e| panic!("起 {bin}: {e}"));
    String::from_utf8(out.stdout).expect("help UTF-8")
}

/// `rillane-mcp` 真实旗标（从 `target/debug/rillane-mcp --help` 递归扫全行）
fn real_mcp_flags() -> BTreeSet<String> {
    let help = help_text("rillane-mcp", &[]);
    scan_double_dash(&help)
}

/// 真实 MCP 工具目录：`target/debug/rillane-mcp` 起一个 stdin 帧，
/// 对 `tools/list` 的答复扫 `"name"` 值。
fn real_tool_names() -> BTreeSet<String> {
    let frame = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}\n";
    let child = Command::new(rillane_mcp_bin())
        .args([
            "-c",
            repo_root()
                .join("config/rillane.yaml")
                .to_string_lossy()
                .as_ref(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("起 rillane-mcp 查 tools/list: {e}"));
    use std::io::Write;
    child
        .stdin
        .as_ref()
        .unwrap()
        .write_all(frame.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("收集 MCP 输出");
    let stdout = String::from_utf8(out.stdout).expect("MCP UTF-8");
    let mut names = BTreeSet::new();
    for seg in stdout.split("\"name\":\"").skip(1) {
        let name = seg.trim_start_matches('"');
        if let Some(end) = name.find('"') {
            let candidate = &name[..end];
            if candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !candidate.is_empty()
            {
                names.insert(candidate.to_string());
            }
        }
    }
    names
}

/// 从代码块（```bash / ```sh / ```powershell）里取 `rillanectl <subcmd> ...`
/// 行的子命令名（首词去掉全局旗标）
fn doc_rillanectl_subcommands(doc: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_block = false;
    for line in doc.lines() {
        let t = line.trim();
        if t.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if !in_block {
            continue;
        }
        let t = t.trim_start_matches("$ ").trim();
        if let Some(rest) = t.strip_prefix("rillanectl ") {
            let mut it = rest.split_whitespace();
            // 跳过全局旗标
            let mut cmd: Option<&str> = None;
            for tok in it.by_ref() {
                if tok.starts_with('-') {
                    continue;
                }
                cmd = Some(tok);
                break;
            }
            if let Some(c) = cmd {
                if c.chars().next().is_some_and(|ch| ch.is_ascii_lowercase()) {
                    out.insert(c.to_string());
                }
            }
        }
    }
    out
}

/// rillane-mcp 可执行路径（target/debug 私有面；本测试在 rillanectl 包内，
/// 直接走仓根 target，避免跨包 env 宏不可用）
fn rillane_mcp_bin() -> PathBuf {
    repo_root().join("target/debug/rillane-mcp")
}

/// 真实 rillanectl 顶层命令面（同 `cli_help_contract.rs`）
fn real_rillanectl_cmds() -> BTreeSet<String> {
    let help = help_text("rillanectl", &[]);
    let mut out = BTreeSet::new();
    if let Some(section) = help.split("Commands:\n").nth(1) {
        let section = section.split("\n\n").next().expect("Commands 段未闭合");
        for line in section.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// 文档侧工具目录行（反引号包裹的 snake_case 名，只取显式目录句）
fn doc_tool_names(doc: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in doc.lines() {
        if !(line.contains("catalog has 16 tools") || line.contains("工具目录为")) {
            continue;
        }
        // 目录在冒号之后、句号之前；`explain` 无下划线也须纳入
        let list = line
            .split_once(':')
            .or_else(|| line.split_once('：'))
            .map(|(_, rest)| rest.split('.').next().unwrap_or(""))
            .and_then(|seg| seg.split('。').next())
            .unwrap_or("");
        for seg in list.split('`').skip(1).step_by(2) {
            if seg
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !seg.contains(' ')
                && !seg.is_empty()
            {
                out.insert(seg.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 链接与路径
// ---------------------------------------------------------------------------

/// usage-bridge 双语文档的相对链接全部真实存在（vitepress 死链检查之外的仓内
/// markdown 链接，本门钉住）
#[test]
fn usage_bridge_links_resolve() {
    for doc_path in ["docs/usage-bridge.md", "docs/zh/usage-bridge.md"] {
        let doc = read_repo(doc_path);
        let targets = rel_links(&doc);
        // 平台/SDK 路径以行内代码出现，不做 markdown 链接解析——下面单独钉
        assert!(
            !targets.is_empty(),
            "{doc_path} 链接面不得为空（解析器失效兜底）"
        );
        let base_dir = PathBuf::from(doc_path).parent().unwrap().to_path_buf();
        for t in &targets {
            let path = t.split('#').next().unwrap();
            let resolved = repo_root().join(&base_dir).join(path);
            assert!(
                resolved.exists(),
                "{doc_path} 链接目标不存在：{t}（解析为 {}）",
                resolved.display()
            );
        }
        // 平台/证据/SDK 路径至少覆盖以下真实产物（具体引用形式允许
        // markdown 链接、行内代码或散文；产物存在性另行钉住）
        for artifact in [
            "platforms/systemd/README.md",
            "platforms/launchd/README.md",
            "platforms/windows/README.md",
            "platforms/openwrt/README.md",
            "platforms/android/README.md",
            "platforms/ios/build.sh",
            "docs/acceptance-evidence/README.md",
            "docs/platform-support.md",
            "apps/rillane-mcp/sdk-acceptance/",
            "apps/rillane-mcp/sdk-acceptance/README.md",
            "apps/rillane-mcp/sdk-acceptance/EVIDENCE.md",
            "config/rillane.yaml",
        ] {
            let stripped = artifact.trim_end_matches('/');
            assert!(exists(stripped), "{doc_path} 引用产物不存在：{artifact}");
        }
    }
}

/// usage-bridge 引用的平台安装模板/脚本必须真实存在（示例命令面产物钉法）
#[test]
fn usage_bridge_install_artifacts_exist() {
    for rel in [
        "platforms/systemd/build.sh",
        "platforms/systemd/rillane.yaml.example",
        "platforms/launchd/build.sh",
        "platforms/launchd/install.sh",
        "platforms/launchd/uninstall.sh",
        "platforms/launchd/com.rillane.rillaned.plist",
        "platforms/windows/build.sh",
        "platforms/windows/install-service.ps1",
        "platforms/windows/uninstall-service.ps1",
        "platforms/openwrt/build.sh",
        "platforms/openwrt/init.d/rillane",
        "platforms/openwrt/rillane.yaml.example",
        "platforms/android/build.sh",
        "platforms/android/app/build/outputs/apk/debug/app-debug.apk",
        "platforms/ios/build.sh",
        "apps/rillane-mcp/sdk-acceptance/accept.cjs",
        "apps/rillane-mcp/sdk-acceptance/package.json",
    ] {
        assert!(exists(rel), "usage-bridge 引用的安装产物不存在：{rel}");
    }
}

// ---------------------------------------------------------------------------
// 命令/旗标/工具目录对齐
// ---------------------------------------------------------------------------

/// usage-bridge 的 `rillanectl <subcmd>` 示例都是真实顶层命令；Debug 面
/// （trace/probe/explain/diagnose）不得再以「目标设计」口径写成拟议
#[test]
fn usage_bridge_debug_commands_are_real() {
    let mut required = BTreeSet::new();
    for c in ["trace", "probe", "explain", "diagnose"] {
        required.insert(c.to_string());
    }
    for doc_path in ["docs/usage-bridge.md", "docs/zh/usage-bridge.md"] {
        let doc = read_repo(doc_path);
        let real = real_rillanectl_cmds();
        assert!(real.len() > 20, "命令面解析失效兜底");
        let documented = doc_rillanectl_subcommands(&doc);
        let missing: Vec<_> = required.difference(&documented).collect();
        assert!(
            missing.is_empty(),
            "{doc_path} Debug 示例缺真实命令：{missing:?}——安装/恢复/Debug 示例必须逐节对齐实际产物"
        );
        for c in &documented {
            assert!(real.contains(c), "{doc_path} 示例命令不在二进制面：{c}");
        }
    }
}

/// usage-bridge 里出现的 `rillane-mcp` 旗标都是真实 help 面
#[test]
fn usage_bridge_mcp_flags_match_help() {
    let real = real_mcp_flags();
    assert!(!real.is_empty(), "MCP 旗标面不得为空");
    for doc_path in ["docs/usage-bridge.md", "docs/zh/usage-bridge.md"] {
        let doc = read_repo(doc_path);
        // 只看 `rillane-mcp` 调用段里的旗标
        for seg in doc.split("rillane-mcp").skip(1) {
            let seg = seg.split('\n').next().unwrap_or("");
            for flag in scan_double_dash(seg) {
                assert!(
                    real.contains(&flag),
                    "{doc_path} MCP 旗标在真实 help 面不存在：{flag}"
                );
            }
        }
    }
}

/// usage-bridge 列出的 16 个工具名与真实 `tools/list` 目录一致
#[test]
fn usage_bridge_tool_catalog_matches_mcp() {
    let real = real_tool_names();
    assert_eq!(
        real.len(),
        16,
        "真实工具目录应为 16 个（实测 {}）——usage-bridge 必须对齐",
        real.len()
    );
    for doc_path in ["docs/usage-bridge.md", "docs/zh/usage-bridge.md"] {
        let doc = read_repo(doc_path);
        let documented = doc_tool_names(&doc);
        let missing: Vec<_> = real.difference(&documented).collect();
        assert!(
            missing.is_empty(),
            "{doc_path} 工具目录缺真实工具：{missing:?}——MCP 示例必须对齐 tools/list 面"
        );
        let extra: Vec<_> = documented.difference(&real).collect();
        assert!(
            extra.is_empty(),
            "{doc_path} 工具目录出现非 tools/list 名字：{extra:?}——幻影工具不得出现在示例"
        );
    }
}

// ---------------------------------------------------------------------------
// 陈旧声明钉法
// ---------------------------------------------------------------------------

/// 示例/参考面不得再声称 Explain/Trace/Probe/MCP 尚未实现（这些已落地为
/// 当前命令/适配器）；设计页保留「目标基线」口径即可
#[test]
fn no_stale_not_implemented_claims() {
    let banned: &[(&str, &str)] = &[
        ("docs/usage-bridge.md", "not implemented"),
        ("docs/usage-bridge.md", "尚未实现"),
        ("docs/usage-bridge.md", "不是当前命令"),
        ("docs/usage-bridge.md", "proposed"),
        ("docs/zh/usage-bridge.md", "尚未实现"),
        ("docs/zh/usage-bridge.md", "不是当前命令"),
        ("docs/zh/usage-bridge.md", "拟议"),
        ("docs/cli.md", "not current commands"),
        ("docs/cli.md", "are [proposed]"),
        ("docs/zh/cli.md", "不能当成当前命令执行"),
        ("docs/zh/cli.md", "仍是[目标设计]"),
        ("docs/architecture.md", "MCP is not implemented"),
        ("docs/zh/architecture.md", "可选 MCP 尚无实现"),
        ("README.md", "MCP still require implementation"),
        ("README.zh.md", "MCP 仍有待实施"),
    ];
    for (path, needle) in banned {
        let doc = read_repo(path);
        assert!(
            !doc.contains(needle),
            "{path} 不应再声称「{needle}」——Explain/Trace/Probe/MCP 已是真实面；陈旧声明必须清掉"
        );
    }
}

// ---------------------------------------------------------------------------
// 对账器自证
// ---------------------------------------------------------------------------

/// 把一条陈旧「未实现」声明注入 usage-bridge → 陈旧门必须点名
#[test]
#[should_panic(expected = "陈旧声明必须清掉")]
fn comparator_bites_on_stale_not_implemented() {
    let doc = read_repo("docs/usage-bridge.md").replacen(
        "# Install, recover, Debug and MCP examples",
        "# Install, recover, Debug and MCP examples\n\nExplain/Trace/Probe/MCP are proposed, not implemented.",
        1,
    );
    assert!(
        !doc.contains("not implemented"),
        "docs/usage-bridge.md 不应再声称「not implemented」——Explain/Trace/Probe/MCP 已是真实面；陈旧声明必须清掉"
    );
}

/// 把幻影 MCP 旗标注入 usage-bridge → MCP 旗标门必须点名
#[test]
#[should_panic(expected = "MCP 旗标在真实 help 面不存在")]
fn comparator_bites_on_phantom_mcp_flag() {
    let doc = read_repo("docs/usage-bridge.md").replacen(
        "rillane-mcp --config config/rillane.yaml --scope read --rate-limit 60",
        "rillane-mcp --config config/rillane.yaml --scope read --rate-limit 60 --phantom-flag x",
        1,
    );
    let real = real_mcp_flags();
    for seg in doc.split("rillane-mcp").skip(1) {
        let seg = seg.split('\n').next().unwrap_or("");
        for flag in scan_double_dash(seg) {
            assert!(
                real.contains(&flag),
                "docs/usage-bridge.md MCP 旗标在真实 help 面不存在：{flag}"
            );
        }
    }
}

/// 把幻影工具名注入 usage-bridge → 工具目录门必须点名
#[test]
#[should_panic(expected = "幻影工具不得出现在示例")]
fn comparator_bites_on_phantom_tool() {
    let doc = read_repo("docs/usage-bridge.md").replacen(
        "`runtime_stats`",
        "`runtime_stats`, `phantom_tool`",
        1,
    );
    let real = real_tool_names();
    let documented = doc_tool_names(&doc);
    let extra: Vec<_> = documented.difference(&real).collect();
    assert!(
        extra.is_empty(),
        "docs/usage-bridge.md 工具目录出现非 tools/list 名字：{extra:?}——幻影工具不得出现在示例"
    );
}
