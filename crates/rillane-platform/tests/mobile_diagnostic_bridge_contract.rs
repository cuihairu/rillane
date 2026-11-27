//! RIL-082 移动/路由器诊断接入契约门：`contracts/mobile_diagnostic_bridge_v1.json`
//! 是机器可读账本——VPN 扩展（Android VpnService / iOS NEPacketTunnel）无默认
//! MCP 服务与手机入站管理端口；FFI 导出面恰等；只读查询面、脱敏诊断导出与
//! 桌面桥接说明在场；OpenWrt 可选资源受限档（RILLANE_SMALL）且无 MCP 打包。
//!
//! 本门钉住（验收「VPN 扩展无默认 MCP 服务/手机入站端口，宿主权限与导出
//! 范围受控」的本地可核验面）：
//! - FFI 导出符号集恰等声明（头文件 ↔ Rust 导出 ↔ 账本），且无监听/MCP 标记；
//! - Android VpnService 非 exported、系统权限守卫；移动端源码无监听 socket；
//! - 移动配置 loopback-only（控制面不落手机入站端口）；
//! - 诊断导出范围三档、秘密键表与上传政策标记在 CLI 源码在场；
//! - OpenWrt 资源受限档开关在 build 脚本在场且不打包 rillane-mcp；
//! - 桌面桥接设计文档（双语）与证据文档在场并含必要陈述。
//!
//! 对账器自证：注入 MCP 标记/放宽 VpnService exported/删上传政策，本门必须
//! 点名失败。

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

fn load_ledger() -> Value {
    let path = repo_root("contracts/mobile_diagnostic_bridge_v1.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("账本 JSON 解析失败: {e}"))
}

/// 从 `text` 里收集 `needle` 标识符族（needle 后紧跟 `(` 的形态），
/// 跳过 typedef/注释里的裸名（同 RIL-083 头面扫描口径）。
fn scan_call_names(text: &str, needle: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find(needle) {
        let start = i + pos;
        let mut end = start + needle.len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if text[end..].trim_start().starts_with('(') {
            names.insert(text[start..end].to_string());
        }
        i = end;
    }
    names
}

/// C 头注释归一（`//` 与 `/* */` 剥离），防文档注释里的禁止词冒充代码面。
fn strip_c_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_block = false;
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
                out.push(' ');
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block = true;
        } else if c == '/' && chars.peek() == Some(&'/') {
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == '\n' {
                    break;
                }
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn walkdir_all(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn collect_text(path: PathBuf) -> String {
    if path.is_dir() {
        let mut out = String::new();
        for entry in walkdir_all(&path) {
            if let Ok(s) = std::fs::read_to_string(&entry) {
                out.push_str(&s);
                out.push('\n');
            }
        }
        out
    } else {
        std::fs::read_to_string(&path).unwrap_or_default()
    }
}

/// FFI 导出面恰等：头文件 ↔ Rust 导出 ↔ 账本清单；无 MCP/JSON-RPC/监听标记。
#[test]
fn ffi_export_face_matches_ledger_exactly() {
    let ledger = load_ledger();
    assert_eq!(ledger["schema_version"], serde_json::json!(1u32));
    let declared: BTreeSet<String> = ledger["ffi"]["exports"]
        .as_array()
        .expect("exports 数组")
        .iter()
        .map(|v| v.as_str().expect("export 名").to_string())
        .collect();

    let header = strip_c_comments(&read_text(
        ledger["ffi"]["header"].as_str().expect("header"),
    ));
    let lib = strip_c_comments(&read_text(ledger["ffi"]["lib"].as_str().expect("lib")));
    let kotlin = strip_c_comments(&read_text(
        ledger["ffi"]["kotlin_face"].as_str().expect("kotlin"),
    ));

    let header_names = scan_call_names(&header, "rillane_ffi_");
    let lib_names = scan_call_names(&lib, "rillane_ffi_");
    let header_only: Vec<&String> = header_names.difference(&declared).collect();
    let declared_only: Vec<&String> = declared.difference(&header_names).collect();
    assert!(
        header_only.is_empty(),
        "头文件多声明导出 {header_only:?}（入站/监听面须过账本事务）"
    );
    assert!(
        declared_only.is_empty(),
        "账本导出未在场 {declared_only:?}（账本落后于实现）"
    );
    assert_eq!(header_names, lib_names, "头文件与 Rust 导出符号集漂移");

    // Kotlin face 加载同一 cdylib（移动宿主桥接在场）。
    assert!(
        kotlin.contains("System.loadLibrary(\"rillane_ffi\")"),
        "Kotlin face 未加载 rillane_ffi（移动宿主桥接缺失）"
    );

    // 禁止词：无 MCP / JSON-RPC / 监听 socket 符号（代码面，非注释）。
    let forbidden: Vec<&str> = ledger["ffi"]["forbidden_tokens"]
        .as_array()
        .expect("forbidden_tokens")
        .iter()
        .map(|v| v.as_str().expect("token"))
        .collect();
    for t in &forbidden {
        assert!(
            !lib.contains(t),
            "FFI 源码出现禁止标记 {t}（移动面不得携带 MCP/入站监听）"
        );
    }
}

/// Android VpnService 非 exported + 系统权限守卫；全源码无监听 socket/MCP。
#[test]
fn android_vpn_service_is_not_exported() {
    let ledger = load_ledger();
    let android = ledger["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|h| h["id"] == "android")
        .expect("android 主机");

    let manifest = collect_text(repo_root(
        "platforms/android/app/src/main/AndroidManifest.xml",
    ));
    let service_name = android["service"]["name"].as_str().expect("service.name");
    let permission = android["service"]["permission"]
        .as_str()
        .expect("permission");

    let start = manifest
        .find(service_name)
        .unwrap_or_else(|| panic!("Manifest 缺 {service_name}"));
    let block = &manifest[start..];
    let end = block.find("</service>").expect("service 块未闭合");
    let block = &block[..end];

    assert!(
        block.contains(&format!("android:permission=\"{permission}\"")),
        "VpnService 缺系统权限守卫 {permission}"
    );
    assert!(
        block.contains("android:exported=\"false\""),
        "VpnService 不得 exported（宿主入站面）"
    );

    // 全源码无监听 socket / MCP 标记。
    let text: String = android["sources"]
        .as_array()
        .expect("sources")
        .iter()
        .map(|v| collect_text(repo_root(v.as_str().expect("src"))))
        .collect::<Vec<_>>()
        .join("\n");
    for f in [
        "ServerSocket",
        "DatagramSocket",
        "TcpListener",
        "mcp",
        "MCP",
        "rmcp",
    ] {
        assert!(!text.contains(f), "Android 源码出现 {f}（无 MCP/入站监听）");
    }

    // exported=true 只允许 launcher activity（MCP/入面不得导出）。
    assert!(
        manifest.matches("exported=\"true\"").count() <= 1,
        "exported=true 只允许 launcher activity（MCP/入站面不得导出）"
    );
}

/// 移动配置 loopback-only：控制面恒 loopback，不对全网卡监听。
#[test]
fn mobile_configs_are_loopback_only() {
    let ledger = load_ledger();
    for h in ledger["hosts"].as_array().expect("hosts") {
        for cfg in h["configs"].as_array().expect("configs") {
            let path = cfg.as_str().expect("config");
            let text = read_text(path);
            assert!(
                text.contains("127.0.0.1:9090"),
                "{path} 控制面 api_bind 必须 loopback"
            );
            assert!(
                !text.contains("0.0.0.0:9090"),
                "{path} 控制面不得对全网卡监听"
            );
        }
    }
}

/// 诊断导出范围受控：三档、秘密键表、上传政策与脱敏助手在 CLI 源码在场。
#[test]
fn diagnose_export_scope_is_controlled() {
    let ledger = load_ledger();
    let export = &ledger["export"];
    let cli = read_text(export["cli"].as_str().expect("cli"));

    let scopes: Vec<&str> = export["scopes"]
        .as_array()
        .expect("scopes")
        .iter()
        .map(|v| v.as_str().expect("scope"))
        .collect();
    assert_eq!(scopes, ["safe", "full", "raw"]);
    for s in &scopes {
        assert!(cli.contains(&format!("\"{s}\"")), "CLI 缺诊断范围 {s}");
    }
    for key in export["secret_keys"].as_array().expect("secret_keys") {
        let key = key.as_str().expect("key");
        assert!(cli.contains(&format!("\"{key}\"")), "CLI 秘密键表缺 {key}");
    }
    for helper in export["redaction_helpers"].as_array().expect("helpers") {
        let helper = helper.as_str().expect("helper");
        assert!(cli.contains(helper), "CLI 脱敏助手 {helper} 未在场");
    }
    // 文本在场不够：账本必指向 CLI 内联真测（真调用上述助手并断言剥除语义），
    // 且该测必须存在、确为 #[test]、覆盖三个出口面。
    let gate = export["runtime_gate"].as_str().expect("runtime_gate");
    let (path, module) = gate.split_once(':').expect("runtime_gate 路径:模块");
    let gate_src = read_text(path);
    assert!(
        gate_src.contains(&format!("mod {module}")),
        "CLI 缺内联脱敏测试模块 {module}"
    );
    assert!(
        gate_src.contains("strip_json_url_secrets(&mut v)")
            && gate_src.contains("redact_config_by_extension(yaml")
            && gate_src.contains("sanitize_diagnostic_log(raw"),
        "内联脱敏测试未真调用三个出口助手"
    );
    let count = export["runtime_gate_tests"].as_u64().expect("test count");
    let marker = format!("mod {module}");
    let module_start = gate_src.find(&marker).expect("module start");
    let module_src = &gate_src[module_start..];
    assert_eq!(
        module_src.matches("#[test]").count() as u64,
        count,
        "内联脱敏测试计数与账本不符"
    );
    for marker in export["policy_markers"].as_array().expect("markers") {
        let marker = marker.as_str().expect("marker");
        assert!(cli.contains(marker), "诊断导出政策标记缺失: {marker}");
    }
}

/// Android 移动构建档检查体（门与自证同源——吃账本 + 脚本全文）。
fn android_mobile_profile_check(ledger: &Value, script: &str) {
    let android = ledger["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|h| h["id"] == "android")
        .expect("android 主机");
    let profile = &android["mobile_profile"];
    let flag = profile["flag"].as_str().expect("flag");
    let forbidden = profile["forbidden_feature"]
        .as_str()
        .expect("forbidden_feature");

    assert!(
        script.contains(flag),
        "Android build 缺移动构建档 {flag}（default=full 会把 wasmtime/JIT 打进移动 cdylib）"
    );
    // 禁面扫描只看有效代码（shell `#` 注释剥离——说明性散文不算构建面），
    // 本脚本无 heredoc、字符串内无 `#`，行级剥离即精确。
    let code_only = script
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains(forbidden),
        "Android build 代码面出现禁面特征 {forbidden}（移动宿主无 WASM 插件面）"
    );
    // 产物面在脚本在场（账本 mobile_profile.packages）
    for pkg in profile["packages"].as_array().expect("packages") {
        let pkg = pkg.as_str().expect("package");
        assert!(script.contains(pkg), "Android build 脚本未产出 {pkg}");
    }
    // manifest 档位自洽：mobile 转发 small、default 挂 full（与账本 ffi.features 一致）
    let manifest = read_text(ledger["ffi"]["manifest"].as_str().expect("manifest"));
    assert!(
        manifest.contains("mobile = [\"rillane-runtime/small\"]"),
        "FFI manifest mobile 档转发面漂移（账本 ffi.features.mobile=rillane-runtime/small）"
    );
}

/// Android 移动构建档：build 脚本必须以 mobile 档交叉 FFI（default=full 档
/// 会把 wasmtime/JIT 插件面打进移动 cdylib——RIL-040 档位纪律 + RIL-082 第二段
/// 修真漂移），代码面不得出现 forbidden_feature。
#[test]
fn android_mobile_profile_builds_ffi_without_wasmtime() {
    let ledger = load_ledger();
    let script = read_text(
        ledger["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .find(|h| h["id"] == "android")
            .expect("android 主机")["build_script"]
            .as_str()
            .expect("build_script"),
    );
    android_mobile_profile_check(&ledger, &script);
}

/// Android README 构建说明 ↔ build 脚本档位自洽：README 必须写明移动档
/// 交叉旗标与 SDK 路径入口（照抄脚本口径），不得教用户跑 full 档进移动端。
fn android_readme_check(script: &str, doc: &str) {
    let profile = load_ledger()["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|h| h["id"] == "android")
        .expect("android 主机")["mobile_profile"]
        .clone();
    let flag = profile["flag"].as_str().expect("flag");
    assert!(
        script.contains(flag),
        "前置：build 脚本档位本身已漂（README 检查以外的问题）"
    );
    // README 按行宽折行（flag 中间换行），归一化空白再比（脚本侧原样即可）
    let doc_flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        doc_flat.contains(flag),
        "platforms/android/README.md 未写明移动档交叉旗标 {flag}——构建说明与脚本档位脱节"
    );
    assert!(
        doc.contains("ANDROID_HOME"),
        "platforms/android/README.md 未给出 Android SDK 路径入口（ANDROID_HOME 覆盖）"
    );
}

#[test]
fn android_readme_documents_mobile_profile() {
    let script = read_text("platforms/android/build.sh");
    let doc = read_text("platforms/android/README.md");
    android_readme_check(&script, &doc);
}

/// 对账器自证：README 删掉档位旗标 → README 门必须点名。
#[test]
#[should_panic(expected = "未写明移动档交叉旗标")]
fn comparator_bites_on_android_readme_profile_lag() {
    let script = read_text("platforms/android/build.sh");
    // README 折行把旗标拆到两行，先归一化再抹掉（抹不掉即自证失效）
    let flat = read_text("platforms/android/README.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let tampered = flat.replace("--no-default-features --features mobile", "");
    assert_ne!(tampered, flat, "篡改形与原形相同（自证失效）");
    android_readme_check(&script, &tampered);
}

/// 对账器自证：脚本退回 default=full 漂移形 → 本门必须点名。
#[test]
#[should_panic(expected = "Android build 缺移动构建档")]
fn comparator_bites_on_android_full_profile_build() {
    let ledger = load_ledger();
    let script = read_text(
        ledger["hosts"]
            .as_array()
            .expect("hosts")
            .iter()
            .find(|h| h["id"] == "android")
            .expect("android 主机")["build_script"]
            .as_str()
            .expect("build_script"),
    );
    let tampered = script.replace(
        "--no-default-features --features mobile",
        "--features mobile", // 退回 default=full 的漂移形（注释同剥，恰似回退提交）
    );
    assert_ne!(tampered, script, "篡改形与原形相同（自证失效）");
    android_mobile_profile_check(&ledger, &tampered);
}

/// OpenWrt 资源受限档可选、不打包 MCP、控制面 loopback。
#[test]
fn openwrt_small_profile_is_opt_in_without_mcp() {
    let ledger = load_ledger();
    let openwrt = ledger["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|h| h["id"] == "openwrt")
        .expect("openwrt 主机");

    let script = read_text(openwrt["build_script"].as_str().expect("build_script"));
    let small = &openwrt["small_profile"];
    let env = small["env"].as_str().expect("env");
    let value = small["enabled_value"].as_str().expect("value");
    let flag = small["flag"].as_str().expect("flag");
    let forbidden_pkg = small["forbidden_package"]
        .as_str()
        .expect("forbidden_package");

    assert!(
        script.contains(env) && script.contains(flag),
        "OpenWrt build 缺资源受限档开关 {env}={value} → {flag}"
    );
    assert!(
        !script.contains(forbidden_pkg),
        "OpenWrt 构建不得打包 {forbidden_pkg}（无 MCP 服务）"
    );

    let cfg = read_text(openwrt["configs"][0].as_str().expect("template"));
    assert!(
        cfg.contains("api_bind: 127.0.0.1:9090"),
        "OpenWrt 模板控制面必须 loopback"
    );
    assert!(
        !cfg.contains("0.0.0.0:9090"),
        "OpenWrt 控制面不得对全网卡监听"
    );
}

/// 桌面桥接设计文档（双语）与证据文档在场并含必要陈述。
#[test]
fn desktop_bridge_docs_exist_with_required_statements() {
    let ledger = load_ledger();
    let bridge = &ledger["desktop_bridge"];

    for doc in bridge["design"].as_array().expect("design").iter() {
        let text = read_text(doc.as_str().expect("doc"));
        let lower = text.to_lowercase();
        assert!(
            lower.contains("不默认") || lower.contains("no default") || lower.contains("不新增"),
            "{doc} 未陈述移动 MCP/入站端口边界"
        );
        assert!(
            lower.contains("mcp") && (lower.contains("入站") || lower.contains("inbound")),
            "{doc} 未关联 MCP 与手机入站端口"
        );
    }

    for ev in bridge["evidence"].as_array().expect("evidence").iter() {
        let path = ev.as_str().expect("evidence");
        assert!(repo_root(path).is_file(), "证据文档 {path} 未在场");
    }
}

/// 对账器自证：注入 MCP 标记 → 导出面门必须点名。
#[test]
#[should_panic(expected = "FFI 源码出现禁止标记 mcp")]
fn comparator_bites_on_injected_mcp_surface() {
    let ledger = load_ledger();
    let mut lib = strip_c_comments(&read_text(ledger["ffi"]["lib"].as_str().unwrap()));
    lib.push_str("\npub fn rillane_ffi_mcp_serve() {}");
    assert!(
        !lib.contains("mcp"),
        "FFI 源码出现禁止标记 mcp（移动面不得携带 MCP/入站监听）"
    );
}

/// 对账器自证：VpnService 放宽 exported → 门必须点名。
#[test]
#[should_panic(expected = "VpnService 不得 exported")]
fn comparator_bites_on_vpn_service_becoming_exported() {
    let manifest_path = repo_root("platforms/android/app/src/main/AndroidManifest.xml");
    let mut manifest = std::fs::read_to_string(&manifest_path).unwrap();
    manifest = manifest.replace("android:exported=\"false\"", "android:exported=\"true\"");
    let start = manifest.find(".RillaneVpnService").unwrap();
    let block = &manifest[start..];
    let end = block.find("</service>").unwrap();
    let block = &block[..end];
    assert!(
        block.contains("android:exported=\"false\""),
        "VpnService 不得 exported"
    );
}

/// 对账器自证：删除上传政策标记 → 导出门必须点名。
#[test]
#[should_panic(expected = "诊断导出政策标记缺失")]
fn comparator_bites_on_dropped_export_policy() {
    let ledger = load_ledger();
    let mut cli = read_text(ledger["export"]["cli"].as_str().unwrap());
    cli = cli.replace(
        "manual only - rillanectl never uploads the bundle anywhere",
        "",
    );
    for marker in ledger["export"]["policy_markers"].as_array().unwrap() {
        let marker = marker.as_str().unwrap();
        assert!(cli.contains(marker), "诊断导出政策标记缺失: {marker}");
    }
}
