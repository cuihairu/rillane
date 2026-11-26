//! RIL-091 第三段：命令 help / REST 表与实际产物对齐契约门。
//!
//! 验收条款「命令 help 与实际产物一致」的机器钉法：真实二进制 help 面
//! （经 `CARGO_BIN_EXE_rillanectl` 起真进程，逐子命令走到三层）与两语
//! `docs/cli.md` 双向恰等——命令总览表（命令集）、旗标集（含嵌套叶命令
//! 如 `trace flow --svg`、`mtls revoke status`）；REST 端点表与
//! `rillaned` 控制面路由表（静态 match 臂 + 动态 guard 前缀族 + /health
//! if 分支）双向恰等；退出码冻结语法（1=用法或连接错误 / 2=显式缺席 /
//! help·version=0）离线实测钉住。
//!
//! 对账器自证：幻影命令行 / 旗标改名，门必须点名失败。
//!
//! 诚实边界：缺席退出码 2 需活 daemon 应答（显式缺席面），归运行批次；
//! 此处只钉本机可实测的用法/连接错误半边。

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("读取 {rel}: {e}"))
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rillanectl"))
        .args(args)
        .output()
        .expect("起 rillanectl 进程")
}

fn help_text(args: &[&str]) -> String {
    let mut full: Vec<&str> = args.to_vec();
    full.push("--help");
    String::from_utf8(run(&full).stdout).expect("help 输出 UTF-8")
}

/// help 的 Commands: 段解析：命令名须 ASCII 小写/数字/连字且后跟 clap
/// 对齐的 ≥2 空格（描述换行的续行是长缩进+CJK，天然滤掉）；help 自身除外
fn commands_from_help(h: &str) -> Vec<String> {
    let Some(section) = h.split("Commands:\n").nth(1) else {
        return Vec::new();
    };
    let section = section.split("\n\n").next().expect("Commands 段未闭合");
    section
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("  ")?.trim_start();
            let name = rest.split_whitespace().next()?;
            let ascii_cmd = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            let aligned = rest[name.len()..].starts_with("  ");
            (ascii_cmd && aligned && name != "help").then(|| name.to_string())
        })
        .collect()
}

/// 顶层命令面（help 的 Commands: 段；help 自身除外）
fn top_commands() -> BTreeSet<String> {
    commands_from_help(&help_text(&[])).into_iter().collect()
}

/// 某命令 help 输出里的子命令名（无则空集）
fn sub_commands(args: &[&str]) -> Vec<String> {
    commands_from_help(&help_text(args))
}

/// 真实旗标全集：顶层 + 每个子命令递归到叶（mtls revoke status 等）
fn real_flags() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut frontier: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(path) = frontier.pop() {
        let refs: Vec<&str> = path.iter().map(String::as_str).collect();
        let h = help_text(&refs);
        for f in scan_flags(&h) {
            out.insert(f);
        }
        for sub in sub_commands(&refs) {
            let mut next = path.clone();
            next.push(sub);
            frontier.push(next);
        }
    }
    out
}

fn scan_flags(text: &str) -> Vec<String> {
    scan_double_dash(text)
}

fn scan_double_dash(text: &str) -> Vec<String> {
    let mut out = Vec::new();
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
            // 至少一个字母（排除 `--` 裸分隔）
            if tok[2..].chars().any(|c| c.is_ascii_alphabetic()) {
                out.push(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

/// 文档侧命令总览表（首格即命令名的表行，两语同形）
fn doc_commands(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .filter(|c| c.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        .map(String::from)
        .collect()
}

/// 文档侧旗标全集（代码块 + 反引号散文，两语合并）
fn doc_flags(doc: &str) -> BTreeSet<String> {
    scan_double_dash(doc).into_iter().collect()
}

// ---------------------------------------------------------------------------
// 命令总览 ↔ 二进制面
// ---------------------------------------------------------------------------

#[test]
fn command_overview_matches_binary() {
    let bin_cmds = top_commands();
    assert!(!bin_cmds.is_empty(), "二进制命令面不得为空");
    for lang in ["docs/cli.md", "docs/zh/cli.md"] {
        let doc = read_repo(lang);
        let doc_cmds = doc_commands(&doc);
        let missing: Vec<_> = bin_cmds.difference(&doc_cmds).collect();
        assert!(
            missing.is_empty(),
            "二进制命令未入文档（{lang}）：{missing:?}——命令 help 与实际产物必须一致"
        );
        let phantom: Vec<_> = doc_cmds.difference(&bin_cmds).collect();
        assert!(
            phantom.is_empty(),
            "文档命令不在二进制面（{lang}）：{phantom:?}——幻影命令不得出现在命令总览"
        );
    }
}

// ---------------------------------------------------------------------------
// 旗标集 ↔ 真实 help 面
// ---------------------------------------------------------------------------

#[test]
fn flags_match_real_help_faces() {
    let real = real_flags();
    assert!(real.len() > 30, "真实旗标面不得为空，实际 {}", real.len());
    for lang in ["docs/cli.md", "docs/zh/cli.md"] {
        let doc = read_repo(lang);
        let documented = doc_flags(&doc);
        let drifting: Vec<_> = documented.difference(&real).collect();
        assert!(
            drifting.is_empty(),
            "文档旗标在真实 help 面不存在（{lang}）：{drifting:?}——改名/删除后文档必须跟上"
        );
        let undocumented: Vec<_> = real.difference(&documented).collect();
        assert!(
            undocumented.is_empty(),
            "真实 help 旗标未入文档（{lang}）：{undocumented:?}——新旗标必须同步两语 CLI 参考"
        );
    }
}

// ---------------------------------------------------------------------------
// REST 端点表 ↔ rillaned 控制面路由
// ---------------------------------------------------------------------------

/// 归一化：模板 `{...}` → `*`，去 query，去首尾斜杠
fn canon_path(p: &str) -> String {
    let no_query = p.split('?').next().unwrap();
    let mut out = String::new();
    let mut in_tmpl = false;
    for c in no_query.chars() {
        match c {
            '{' => {
                in_tmpl = true;
                out.push('*');
            }
            '}' => in_tmpl = false,
            c if !in_tmpl => out.push(c),
            _ => {}
        }
    }
    out.trim_matches('/').to_string()
}

/// 控制面路由全集（canonical）：静态 match 臂 + 动态 guard 前缀族；
/// /health 是 match 前的 if 分支，单独以字面量在场钉住
fn control_plane_routes(src: &str) -> (BTreeSet<(String, String)>, bool) {
    let mut routes = BTreeSet::new();
    // 静态：(Method::GET, "/path") => ...
    for cap in regex_static_routes(src) {
        routes.insert(cap);
    }
    // 动态 guard：(Method::POST, p) if p.starts_with("/subscriptions/") [&& p.ends_with("/refresh")]
    for (method, prefix, suffix) in regex_guard_routes(src) {
        let canon = match suffix {
            Some(sfx) => format!("{prefix}*{sfx}"),
            None => format!("{prefix}*"),
        };
        routes.insert((method, canon_path(&canon)));
    }
    let health = src.contains("\"/health\"");
    (routes, health)
}

fn regex_static_routes(src: &str) -> BTreeSet<(String, String)> {
    // 手写扫描，避免引入 regex 依赖：找 "(Method::X, " 模式
    let mut out = BTreeSet::new();
    let needle = "(Method::";
    let mut rest = src;
    while let Some(pos) = rest.find(needle) {
        let tail = &rest[pos + needle.len()..];
        // X, "/path")
        let Some(close) = tail.find(')') else { break };
        let inner = &tail[..close];
        if let Some((method, path)) = parse_method_path(inner) {
            out.insert((method, canon_path(&path)));
        }
        rest = &tail[close..];
    }
    out
}

fn parse_method_path(inner: &str) -> Option<(String, String)> {
    let inner = inner.trim();
    let (method, rest) = inner.split_once(',')?;
    let method = method.trim().to_string();
    let path = rest.trim().trim_matches('"').to_string();
    // guard 臂的内层是 `POST, p`（路径为 guard 变量），不以 / 开头即排除
    path.starts_with('/').then_some((method, path))
}

fn regex_guard_routes(src: &str) -> Vec<(String, String, Option<String>)> {
    // (Method::POST, p) if p.starts_with("/x/") [&& p.ends_with("/y")]
    let mut out = Vec::new();
    for seg in src.split("(Method::") {
        let Some((head, after)) = seg.split_once(", p) if p.starts_with(") else {
            continue;
        };
        let method = head.trim().to_string();
        let rest = &after[1..]; // 跳过引号
        let Some(close) = rest.find('"') else {
            continue;
        };
        let prefix = rest[..close].to_string();
        let suffix = rest[close..]
            .split_once("ends_with(\"")
            .and_then(|(_, s)| s.split('"').next())
            .map(String::from);
        out.push((method, prefix, suffix));
    }
    out
}

/// 文档 REST 表行：(Method, canonical path)
fn doc_rest_rows(doc: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in doc.lines() {
        let Some(row) = line.strip_prefix("| ") else {
            continue;
        };
        let mut cells = row.split('|');
        let method = cells.next().unwrap_or("").trim().to_string();
        let path_cell = cells.next().unwrap_or("").trim().to_string();
        if !["GET", "POST", "DELETE", "PUT", "PATCH"].contains(&method.as_str()) {
            continue;
        }
        let Some(path) = path_cell
            .strip_prefix('`')
            .and_then(|p| p.strip_suffix('`'))
            .map(String::from)
        else {
            continue;
        };
        out.insert((method, canon_path(&path)));
    }
    out
}

#[test]
fn rest_table_matches_control_plane_routes() {
    let src = read_repo("apps/rillaned/src/control_plane.rs");
    let (routes, health_in_code) = control_plane_routes(&src);
    assert!(!routes.is_empty(), "控制面路由面不得为空");
    assert!(health_in_code, "/health 应在控制面源码在场");

    for lang in ["docs/cli.md", "docs/zh/cli.md"] {
        let doc = read_repo(lang);
        let doc_rows = doc_rest_rows(&doc);
        assert!(
            doc_rows.contains(&("GET".into(), "health".into())),
            "{lang} REST 表缺 /health 行"
        );
        for (method, path) in &routes {
            assert!(
                doc_rows.contains(&(method.clone(), path.clone())),
                "控制面路由未入 CLI 文档 REST 表（{lang}）：{method} /{path}——REST 端点表必须与控制面路由一致"
            );
        }
        // 反向：文档 REST 行（除 /health）必须有代码路由承载
        for (method, path) in &doc_rows {
            if path == "health" {
                continue;
            }
            assert!(
                routes.contains(&(method.clone(), path.clone())),
                "文档 REST 行在控制面无路由（{lang}）：{method} /{path}——幻影端点不得出现在文档"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 退出码冻结语法（离线半边）
// ---------------------------------------------------------------------------

fn unreachable_config() -> PathBuf {
    // 指向必关闭端口（:1）的配置，连接错误确定性触发
    let dir = std::env::temp_dir().join("rillanectl-exit-code-contract");
    std::fs::create_dir_all(&dir).expect("临时目录");
    let cfg = dir.join("rillane.yaml");
    std::fs::write(
        &cfg,
        "control:\n  api_bind: 127.0.0.1:1\n  uds_path: null\n  admin_token: \"\"\ntelemetry:\n  log_level: warn\n  enable_metrics: false\n  enable_tracing: false\ningress:\n  - name: socks-in\n    type: socks5\n    bind: 127.0.0.1:19998\negress:\n  - name: direct-main\n    type: direct\nrouting:\n  default_node: direct-main\n  groups: []\n  rules: []\n",
    )
    .expect("写临时配置");
    cfg
}

/// 冻结语法：1=用法或连接错误；help/version=0（2=显式缺席需活 daemon，归运行批次）
#[test]
fn exit_codes_follow_frozen_syntax() {
    // 用法错误半边：缺参 / 未知旗标 / 客户端校验拒绝 → 1（不得顶掉缺席码 2）
    for args in [
        vec!["trace", "flow"], // 缺必需位置参
        vec!["--bad-flag"],    // 未知旗标
        vec!["explain", "h.example", "--port", "443", "--proto", "smtp"], // 客户端校验拒绝
    ] {
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "用法错误应退出 1（冻结语法），实际 {:?}：{:?}",
            out.status.code(),
            args
        );
    }

    // 连接错误半边：控制面必关闭端口 → 1
    let cfg = unreachable_config();
    let cfg_str = cfg.to_string_lossy().into_owned();
    let out = run(&["-c", &cfg_str, "trace", "flow", "abc"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "控制面不可达应退出 1（冻结语法）"
    );

    // help / version → 0
    for args in [vec!["--help"], vec!["--version"], vec!["trace", "--help"]] {
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "help/version 应退出 0，实际 {:?}：{:?}",
            out.status.code(),
            args
        );
    }
}

// ---------------------------------------------------------------------------
// 对账器自证
// ---------------------------------------------------------------------------

/// 幻影命令行混入文档 → 命令门必须点名
#[test]
#[should_panic(expected = "文档命令不在二进制面")]
fn comparator_bites_on_phantom_command() {
    let mut doc = read_repo("docs/cli.md");
    doc = doc.replacen(
        "| `check` |",
        "| `phantom-cmd` | ghost | offline |\n| `check` |",
        1,
    );
    let bin_cmds = top_commands();
    let doc_cmds = doc_commands(&doc);
    let phantom: Vec<_> = doc_cmds.difference(&bin_cmds).collect();
    assert!(
        phantom.is_empty(),
        "文档命令不在二进制面：{phantom:?}——幻影命令不得出现在命令总览"
    );
}

/// 旗标在文档里被改名 → 旗标门必须点名
#[test]
#[should_panic(expected = "文档旗标在真实 help 面不存在")]
fn comparator_bites_on_flag_drift() {
    let doc = read_repo("docs/cli.md").replacen("--svg", "--svg-legacy", 1);
    let real = real_flags();
    let documented = doc_flags(&doc);
    let drifting: Vec<_> = documented.difference(&real).collect();
    assert!(
        drifting.is_empty(),
        "文档旗标在真实 help 面不存在：{drifting:?}——改名/删除后文档必须跟上"
    );
}
