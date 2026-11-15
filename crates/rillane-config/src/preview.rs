//! 提案验证与变更预览（RIL-074）：纯推演面——把提案补丁应用到当前配置的
//! 序列化副本上（RFC 7396 JSON Merge Patch 语义），产出四份报告：
//!
//! 1. **规范化 diff**：当前配置 → 补丁后配置的逐路径差异（键序规范、
//!    数组位置对齐），秘密键路径一律占位脱敏；
//! 2. **引用/能力校验诊断**：补丁应用后的配置走与守护进程装配同一校验链
//!    （路由引用图/块值域 + `CapabilitySet` 组合门）——校验失败即
//!    `applicable=false`，提案不得进入后续授权/Apply；
//! 3. **受影响流类别预测**：由 diff 路径投影的类别级影响——恒标注「预测」，
//!    只描述「新流将按新配置求值、既有连接不重演」，绝不冒充实际连接结果；
//! 4. **副作用提示**：`network` 块路径映射的系统接管层副作用种类（路由表、
//!    TUN 设备、DNS 监听、fwmark）——预览不预执行，提示 Apply 侧经
//!    side_effects 所有权登记。
//!
//! 验收锚点：**校验不改变有效配置**（入参全借用，应用发生在序列化副本上，
//! 纯函数无时钟无 IO）；**诊断与 diff 脱敏**（秘密键的祖先路径一律占位，
//! serde 错误文案不回显补丁值）；**预测影响不冒充实测**（类别注记恒带
//! 「预测」边界）。提案范围外的路径在此仅**报告**（`scope_violations`），
//! 授权执行归 RIL-075/076。

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::contract::CapabilitySet;
use crate::RillaneConfig;

/// 稳定原因码：补丁非法（合并后反序列化失败——形状/类型/版本门）。
pub const CODE_PREVIEW_PATCH_INVALID: &str = "preview.patch.invalid";
/// 稳定原因码：补丁应用后的配置整体校验未通过（引用图/块值域/能力组合）。
pub const CODE_PREVIEW_CONFIG_INVALID: &str = "preview.config.invalid";

/// 秘密键名集合（逐段匹配——祖先路径命中即整棵子树占位）：diff 与预测
/// 注记绝不携带这些键下的任何值。
const SECRET_KEYS: &[&str] = &[
    "password",
    "private_key",
    "preshared_key",
    "bearer_tokens",
    "auth_str",
    "auth",
    "admin_token",
    "token",
];

/// 秘密占位符（不带长度——长度本身也是侧信道）。
const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// diff 条目操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffOp {
    /// 补丁新增的路径
    Added,
    /// 补丁删除的路径
    Removed,
    /// 补丁修改的路径
    Changed,
}

impl DiffOp {
    /// 稳定字面量（机器口径）
    pub fn as_str(self) -> &'static str {
        match self {
            DiffOp::Added => "added",
            DiffOp::Removed => "removed",
            DiffOp::Changed => "changed",
        }
    }
}

/// 规范化 diff 条目：点分路径（对象键按字典序、数组按位置索引），before/
/// after 为脱敏后的 JSON 值（秘密路径恒占位）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffEntry {
    pub op: DiffOp,
    /// 规范化路径（如 `routing.default_node`、`egress.0.password`）
    pub path: String,
    /// 变更前值（脱敏后；added 时为 null）
    pub before: Value,
    /// 变更后值（脱敏后；removed 时为 null）
    pub after: Value,
}

/// 校验诊断：稳定原因码 + 人读消息（消息不回显补丁值——防秘密经
/// serde 错误文案泄漏）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewDiagnostic {
    /// 稳定原因码（`preview.patch.invalid` / `preview.config.invalid` /
    /// `config.combo.unsupported` 等契约码）
    pub code: &'static str,
    /// 人读消息（已脱敏——不含补丁值原文）
    pub message: String,
}

/// 受影响流类别预测（由 diff 路径投影）：恒为**预测**——只描述新流将按
/// 新配置求值，绝不冒充实际连接结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AffectedCategory {
    /// 类别名（routing / endpoints / dns / udp / relay / platform / management）
    pub category: &'static str,
    /// 预测注记（恒含「预测」边界——新流重演、既有连接不重演）
    pub note: &'static str,
    /// 触发本类别的 diff 路径（脱敏后）
    pub paths: Vec<String>,
}

/// 系统接管层副作用提示：预览不预执行——提示 Apply 侧需经 side_effects
/// 所有权登记/撤销（RIL-019 执行侧接线）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SideEffectHint {
    /// 触发路径
    pub path: String,
    /// 副作用种类（route / tun-device / dns-listen / dns-config / fwmark）
    pub kind: &'static str,
    /// 提示注记
    pub note: &'static str,
}

/// 提案预览报告（RIL-074）：全部字段为脱敏后的报告面——本结构可安全
/// 进入答复/日志面。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigPreview {
    /// 补丁应用后的配置是否通过全部校验（反序列化 + 整体校验链 + 能力门）
    pub applicable: bool,
    /// 规范化 diff（脱敏后）
    pub diff: Vec<DiffEntry>,
    /// 校验诊断（空 = 全部通过）
    pub diagnostics: Vec<PreviewDiagnostic>,
    /// 受影响流类别预测
    pub affected: Vec<AffectedCategory>,
    /// 系统接管层副作用提示
    pub side_effects: Vec<SideEffectHint>,
    /// 提案范围外的 diff 路径（仅报告——授权执行归 RIL-075/076；
    /// scope = None 时恒空）
    pub scope_violations: Vec<String>,
}

/// RFC 7396 JSON Merge Patch：对象递归合并、null 删除键、非对象补丁
/// 整体替换。提案补丁（`ConfigProposal.patch`）按此语义应用。
pub fn merge_patch(target: &Value, patch: &Value) -> Value {
    match patch {
        Value::Object(fields) => {
            let mut out = match target {
                Value::Object(map) => map.clone(),
                _ => Map::new(),
            };
            for (key, value) in fields {
                if value.is_null() {
                    out.remove(key);
                } else {
                    let base = out.get(key).cloned().unwrap_or(Value::Null);
                    out.insert(key.clone(), merge_patch(&base, value));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// 预览入口（纯函数）：对当前配置应用补丁并产出四份报告。不改变任何
/// 有效状态——`current` 只被借用，应用发生在序列化副本上。
pub fn preview_config_patch(
    current: &RillaneConfig,
    patch: &Value,
    capabilities: &CapabilitySet,
    scope: Option<&[String]>,
) -> ConfigPreview {
    let current_value = serde_json::to_value(current).expect("有效配置序列化不可失败");
    let merged = merge_patch(&current_value, patch);
    let mut diff = Vec::new();
    diff_values(&current_value, &merged, "", &mut diff);

    let mut preview = ConfigPreview {
        applicable: true,
        diff,
        diagnostics: Vec::new(),
        affected: Vec::new(),
        side_effects: Vec::new(),
        scope_violations: Vec::new(),
    };
    project_reports_into(&mut preview, scope);

    match serde_json::from_value::<RillaneConfig>(merged) {
        Ok(patched) => {
            for issue in validate_whole(&patched) {
                preview.diagnostics.push(PreviewDiagnostic {
                    code: CODE_PREVIEW_CONFIG_INVALID,
                    message: issue,
                });
                preview.applicable = false;
            }
            if let Err(err) = capabilities.validate_config(&patched) {
                preview.diagnostics.push(PreviewDiagnostic {
                    code: err.code(),
                    message: err.to_string(),
                });
                preview.applicable = false;
            }
        }
        Err(_) => {
            preview.diagnostics.push(PreviewDiagnostic {
                code: CODE_PREVIEW_PATCH_INVALID,
                message: "补丁应用后配置反序列化失败（形状/类型/版本不合法）——详见 diff 定位"
                    .to_string(),
            });
            preview.applicable = false;
        }
    }
    preview
}

/// 把 diff 路径投影进 affected / side_effects / scope_violations。
fn project_reports_into(preview: &mut ConfigPreview, scope: Option<&[String]>) {
    let mut affected: Vec<AffectedCategory> = Vec::new();
    let mut side_effects: Vec<SideEffectHint> = Vec::new();
    for entry in &preview.diff {
        let top = entry.path.split('.').next().unwrap_or("");
        if let Some((category, note)) = category_of(top, &entry.path) {
            match affected.iter_mut().find(|a| a.category == category) {
                Some(slot) => slot.paths.push(entry.path.clone()),
                None => affected.push(AffectedCategory {
                    category,
                    note,
                    paths: vec![entry.path.clone()],
                }),
            }
        }
        if top == "network" {
            if let Some((kind, note)) = side_effect_of(&entry.path) {
                side_effects.push(SideEffectHint {
                    path: entry.path.clone(),
                    kind,
                    note,
                });
            }
        }
        if let Some(scope) = scope {
            let in_scope = scope.iter().any(|s| s == top);
            if !in_scope {
                preview.scope_violations.push(entry.path.clone());
            }
        }
    }
    preview.affected = affected;
    preview.side_effects = side_effects;
}

/// 类别投影：diff 顶层段 → 受影响流类别（注记恒含「预测」边界）。
fn category_of(top: &str, path: &str) -> Option<(&'static str, &'static str)> {
    match top {
        "routing" => Some((
            "routing",
            "预测：路由规则/组/场景变更后，新流按新配置重演求值；既有已建立连接钉在原代际不重演（预测不冒充实测）",
        )),
        "ingress" | "egress" => Some((
            "endpoints",
            "预测：入口/出口端点变更后，新连接按新端点建立；既有连接维持原路径（预测不冒充实测）",
        )),
        "udp" => Some((
            "udp",
            "预测：UDP 数据面参数变更后，新会话按新参数；既有会话沿用建立时参数（预测不冒充实测）",
        )),
        "obfuscation" | "egress_pool" | "performance" => Some((
            "relay",
            "预测：转发链行为（混淆/连接池/缓冲）变更后，新连接按新行为；既有连接不回切（预测不冒充实测）",
        )),
        "network" => {
            if path.contains(".dns") {
                Some((
                    "dns",
                    "预测：DNS 分流行为变更后，新解析按新分流；既有缓存/映射不清空（预测不冒充实测）",
                ))
            } else {
                Some((
                    "platform",
                    "预测：网络接管块变更后，接管面按新块重建；需系统副作用（见 side_effects）（预测不冒充实测）",
                ))
            }
        }
        "control" | "telemetry" => Some((
            "management",
            "预测：管理面参数变更，重装配后生效；不影响数据面转发（预测不冒充实测）",
        )),
        _ => None,
    }
}

/// 副作用投影：network 块路径 → 系统接管层副作用种类。
fn side_effect_of(path: &str) -> Option<(&'static str, &'static str)> {
    if path.starts_with("network.routing") {
        Some((
            "route",
            "需内核路由表变更——Apply 侧经 side_effects 所有权登记、逆序撤销（RIL-019 执行侧接线）",
        ))
    } else if path.starts_with("network.dns.listen_") {
        Some((
            "dns-listen",
            "需本地 DNS 监听套接字变更——Apply 侧副作用经所有权登记",
        ))
    } else if path.starts_with("network.dns") {
        Some((
            "dns-config",
            "DNS 引擎配置变更——预览不预启动监听，Apply 侧生效",
        ))
    } else if path.starts_with("network.tun")
        || path == "network"
        || path.starts_with("network.mode")
    {
        Some((
            "tun-device",
            "需 TUN 设备/地址/模式变更——Apply 侧副作用经所有权登记",
        ))
    } else if path.starts_with("network.egress_fwmark") {
        Some((
            "fwmark",
            "需 fwmark 逃逸规则变更——Apply 侧副作用经所有权登记",
        ))
    } else {
        None
    }
}

/// 整体校验链（与守护进程装配同一组块校验）：收集全部人读问题——
/// 这些消息含组名/规则名等定位信息（非秘密值），可进入诊断面。
fn validate_whole(config: &RillaneConfig) -> Vec<String> {
    let mut issues = Vec::new();
    if let Err(err) = config.routing.validate() {
        issues.push(err.to_string());
    }
    if let Err(err) = config.udp.validate() {
        issues.push(err.to_string());
    }
    if let Some(block) = &config.performance {
        if let Err(err) = block.validate() {
            issues.push(err.to_string());
        }
    }
    if let Some(block) = &config.network {
        if let Err(err) = block.validate() {
            issues.push(err.to_string());
        }
    }
    if let Some(block) = &config.obfuscation {
        if let Err(err) = block.validate() {
            issues.push(err.to_string());
        }
    }
    if let Some(block) = &config.egress_pool {
        if let Err(err) = block.validate() {
            issues.push(err.to_string());
        }
    }
    if let Some(block) = &config.probe {
        if let Err(err) = block.validate() {
            issues.push(err.to_string());
        }
    }
    issues
}

/// 规范化 diff（键序字典序、数组位置对齐）：产出脱敏后的条目流。
fn diff_values(base: &Value, after: &Value, path: &str, out: &mut Vec<DiffEntry>) {
    match (base, after) {
        (Value::Object(b), Value::Object(a)) => {
            let mut keys: BTreeSet<&String> = b.keys().collect();
            keys.extend(a.keys());
            for key in keys {
                let child = join_key(path, key);
                match (b.get(key), a.get(key)) {
                    (Some(bv), Some(av)) => diff_values(bv, av, &child, out),
                    (Some(bv), None) => push_entry(out, DiffOp::Removed, &child, Some(bv), None),
                    (None, Some(av)) => push_entry(out, DiffOp::Added, &child, None, Some(av)),
                    (None, None) => unreachable!("键来自两侧并集"),
                }
            }
        }
        (Value::Array(b), Value::Array(a)) => {
            // 位置对齐：长度差即尾部 added/removed——不做语义配对，
            // 索引位移诚实报告（规范化位置 diff）
            let len = b.len().max(a.len());
            for i in 0..len {
                let child = join_index(path, i);
                match (b.get(i), a.get(i)) {
                    (Some(bv), Some(av)) => diff_values(bv, av, &child, out),
                    (Some(bv), None) => push_entry(out, DiffOp::Removed, &child, Some(bv), None),
                    (None, Some(av)) => push_entry(out, DiffOp::Added, &child, None, Some(av)),
                    (None, None) => unreachable!("索引 < max(len)"),
                }
            }
        }
        (b, a) if b != a => push_entry(out, DiffOp::Changed, path, Some(b), Some(a)),
        _ => {}
    }
}

fn push_entry(
    out: &mut Vec<DiffEntry>,
    op: DiffOp,
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
) {
    let redacted = is_secret_path(path);
    let render = |v: Option<&Value>| -> Value {
        match v {
            Some(_) if redacted => Value::from(REDACTED_PLACEHOLDER),
            Some(v) => v.clone(),
            None => Value::Null,
        }
    };
    out.push(DiffEntry {
        op,
        path: path.to_string(),
        before: render(before),
        after: render(after),
    });
}

/// 秘密路径判定：任一路径段命中秘密键即整棵子树占位（祖先命中也脱敏
/// ——整块替换的凭据数组不得经 mismatched-shape 条目泄漏）。
fn is_secret_path(path: &str) -> bool {
    path.split('.').any(|seg| SECRET_KEYS.contains(&seg))
}

fn join_key(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn join_index(path: &str, index: usize) -> String {
    if path.is_empty() {
        index.to_string()
    } else {
        format!("{path}.{index}")
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    fn base_config() -> RillaneConfig {
        RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
            Some("yaml"),
        )
        .expect("基线配置应解析")
    }

    fn full_caps() -> CapabilitySet {
        CapabilitySet::full()
    }

    #[test]
    fn merge_patch_semantics() {
        let base = serde_json::json!({"a": {"b": 1, "c": 2}, "d": 3});
        // null 删除、嵌套合并保留兄弟键、非对象整体替换
        let patched = merge_patch(
            &base,
            &serde_json::json!({"a": {"b": null, "b2": 9}, "d": null, "e": [1]}),
        );
        assert_eq!(
            patched,
            serde_json::json!({"a": {"c": 2, "b2": 9}, "e": [1]}),
            "RFC 7396 语义：null 删、合并留兄弟、新增落位"
        );
        // 非对象补丁 = 整体替换
        assert_eq!(
            merge_patch(&base, &serde_json::json!([])),
            serde_json::json!([])
        );
    }

    #[test]
    fn empty_patch_is_noop_preview() {
        let cfg = base_config();
        let preview = preview_config_patch(&cfg, &serde_json::json!({}), &full_caps(), None);
        assert!(preview.applicable, "空补丁 = 基线配置自身合法");
        assert!(preview.diff.is_empty(), "空补丁无 diff");
        assert!(preview.diagnostics.is_empty());
        assert!(preview.affected.is_empty());
        assert!(preview.side_effects.is_empty());
        assert!(preview.scope_violations.is_empty());
    }

    #[test]
    fn diff_normalizes_changed_added_removed() {
        let cfg = base_config();
        let patch = serde_json::json!({
            "routing": {"default_node": "proxy"},
            "profile": null,
            "telemetry": {"enable_metrics": true}
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);

        let changed = preview
            .diff
            .iter()
            .find(|e| e.path == "routing.default_node")
            .expect("变更条目应在 diff 内");
        assert_eq!(changed.op, DiffOp::Changed);
        assert_eq!(changed.before, serde_json::json!("direct"));
        assert_eq!(changed.after, serde_json::json!("proxy"));

        let removed = preview
            .diff
            .iter()
            .find(|e| e.path == "profile")
            .expect("null 合并删除 → removed");
        assert_eq!(removed.op, DiffOp::Removed);

        let added = preview
            .diff
            .iter()
            .find(|e| e.path == "telemetry.enable_metrics")
            .expect("false→true 为 changed");
        assert_eq!(added.op, DiffOp::Changed);
        assert!(
            preview.diff.iter().any(|e| e.op == DiffOp::Removed),
            "至少含一个 removed（profile）"
        );
    }

    #[test]
    fn diff_redacts_secret_subtrees() {
        let cfg = RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: topsecret\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress:\n  - name: p\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    username: u1\n    password: s3cret\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
            Some("yaml"),
        )
        .expect("含凭据基线应解析");
        let patch = serde_json::json!({
            "egress": [
                {"name": "p", "type": "socks5", "server": "127.0.0.1",
                 "port": 1080, "username": "u2", "password": "n3ws3cret"}
            ]
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        let rendered = serde_json::to_string(&preview).expect("报告可序列化");
        assert!(
            !rendered.contains("s3cret") && !rendered.contains("topsecret"),
            "秘密值不得出现在任何报告面: {rendered}"
        );
        let entry = preview
            .diff
            .iter()
            .find(|e| e.path == "egress.0.password")
            .expect("密码路径条目应在 diff 内");
        assert_eq!(entry.before, serde_json::json!(REDACTED_PLACEHOLDER));
        assert_eq!(entry.after, serde_json::json!(REDACTED_PLACEHOLDER));
        // 阳性对照：非秘密同层字段照常可见（证明脱敏没把整份 diff 打哑）
        let user = preview
            .diff
            .iter()
            .find(|e| e.path == "egress.0.username")
            .expect("username 变更条目应在 diff 内");
        assert_eq!(user.before, serde_json::json!("u1"));
        assert_eq!(user.after, serde_json::json!("u2"));
    }

    #[test]
    fn invalid_patch_reports_stable_code_without_echo() {
        let cfg = base_config();
        let preview = preview_config_patch(
            &cfg,
            &serde_json::json!({"control": {"api_bind": 12345}}),
            &full_caps(),
            None,
        );
        assert!(!preview.applicable);
        assert_eq!(
            preview.diagnostics[0].code, CODE_PREVIEW_PATCH_INVALID,
            "类型不合法 → 稳定码"
        );
        let msg = &preview.diagnostics[0].message;
        assert!(!msg.contains("12345"), "诊断消息不回显补丁值: {msg}");
        // diff 仍列出肇事路径（形状侦察靠 diff，不靠错误文案）
        assert!(
            preview
                .diff
                .iter()
                .any(|e| e.path == "control.api_bind" && e.op == DiffOp::Changed),
            "diff 定位肇事路径"
        );
    }

    #[test]
    fn reference_validation_reports_dangling_selection() {
        let cfg = base_config();
        let patch = serde_json::json!({
            "routing": {"selections": {"auto": "node-a"}}
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        assert!(!preview.applicable, "悬空选择引用 → applicable=false");
        assert!(
            preview
                .diagnostics
                .iter()
                .any(|d| d.code == CODE_PREVIEW_CONFIG_INVALID),
            "整体校验链诊断: {:?}",
            preview.diagnostics
        );
        assert!(
            preview
                .diagnostics
                .iter()
                .any(|d| d.message.contains("未声明的组")),
            "引用错误消息点名: {:?}",
            preview.diagnostics
        );
    }

    #[test]
    fn capability_gate_reports_unsupported_combo() {
        let cfg = base_config();
        let caps = CapabilitySet {
            udp_forwarding: false,
            tun_ingress: false,
            dns_partition: false,
            obfuscation: false,
            egress_pool: false,
            process_attribution: false,
        };
        let preview = preview_config_patch(
            &cfg,
            &serde_json::json!({"udp": {"enabled": true}}),
            &caps,
            None,
        );
        assert!(!preview.applicable);
        assert!(
            preview
                .diagnostics
                .iter()
                .any(|d| d.code == "config.combo.unsupported"),
            "能力门稳定码透传: {:?}",
            preview.diagnostics
        );
    }

    /// 验收「校验不改变有效配置」：纯函数借用入参，连续两次预览后
    /// 当前配置逐字节不变。
    #[test]
    fn preview_does_not_mutate_current_config() {
        let cfg = base_config();
        let before = serde_json::to_string(&cfg).expect("序列化");
        let patch = serde_json::json!({
            "routing": {"default_node": "proxy"},
            "network": {"mode": "tun", "routing": {"include": ["10.0.0.0/8"]}}
        });
        let _first =
            preview_config_patch(&cfg, &patch, &full_caps(), Some(&["routing".to_string()]));
        let _second = preview_config_patch(&cfg, &patch, &full_caps(), None);
        let after = serde_json::to_string(&cfg).expect("序列化");
        assert_eq!(before, after, "预览不得改变有效配置");
    }

    /// 类别投影：块内变更产生子路径 diff → routing/udp/dns 三类别；
    /// 注记恒带「预测」边界。
    #[test]
    fn affected_categories_project_from_diff_paths() {
        // 基线已含 network.dns 块——块内变更才有子路径 diff（整块新增在
        // 类型变更边界收拢为单条目，见 whole_block_addition 测试）
        let cfg = RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\nudp:\n  enabled: false\n  session_idle_secs: 180\nnetwork:\n  mode: tun\n  tun:\n    mtu: 1500\n  routing:\n    include: []\n  dns:\n    enabled: true\n    rules:\n      - pattern: \".cn\"\n        group: domestic\n",
            Some("yaml"),
        )
        .expect("含 DNS 块基线应解析");
        let patch = serde_json::json!({
            "routing": {"default_node": "proxy"},
            "udp": {"session_idle_secs": 120},
            "network": {"dns": {"rules": [{"pattern": ".com", "group": "trusted"}]}}
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        let categories: Vec<&str> = preview.affected.iter().map(|a| a.category).collect();
        assert!(categories.contains(&"routing"), "类别: {categories:?}");
        assert!(categories.contains(&"udp"), "类别: {categories:?}");
        assert!(
            categories.contains(&"dns"),
            "network.dns 子路径 → dns 类别: {categories:?}"
        );
        for a in &preview.affected {
            assert!(a.note.contains("预测"), "注记恒带预测边界: {}", a.note);
            assert!(!a.paths.is_empty(), "类别须携带触发路径");
        }
    }

    /// 整块新增在类型变更边界收拢为单条目（network null→对象）——
    /// 投影为 platform 类别 + tun-device 副作用，不伪造子路径。
    #[test]
    fn whole_block_addition_collapses_to_block_entry() {
        let cfg = base_config();
        let patch = serde_json::json!({
            "network": {"mode": "tun", "routing": {"include": ["10.0.0.0/8"]}}
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        assert!(
            preview
                .diff
                .iter()
                .any(|e| e.path == "network" && e.op == DiffOp::Changed),
            "整块新增 = 单条目: {:?}",
            preview.diff
        );
        assert!(
            preview.affected.iter().any(|a| a.category == "platform"),
            "network 非子路径 → platform 类别: {:?}",
            preview.affected
        );
        assert!(
            preview
                .side_effects
                .iter()
                .any(|s| s.kind == "tun-device" && s.path == "network"),
            "整块新增 → tun-device 副作用提示: {:?}",
            preview.side_effects
        );
    }

    /// 副作用投影：network 块内子路径变更 → route/tun-device；非 network
    /// 变更零副作用提示。
    #[test]
    fn side_effects_report_network_paths_only() {
        let cfg = RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress: []\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\nnetwork:\n  mode: tun\n  tun:\n    mtu: 1500\n  routing:\n    include: []\n",
            Some("yaml"),
        )
        .expect("含 network 块基线应解析");
        let patch = serde_json::json!({
            "network": {"routing": {"include": ["10.0.0.0/8"]},
                        "tun": {"mtu": 1400}},
            "routing": {"default_node": "proxy"}
        });
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        let kinds: Vec<&str> = preview.side_effects.iter().map(|s| s.kind).collect();
        assert!(
            kinds.contains(&"route"),
            "network.routing.include → route: {kinds:?}"
        );
        assert!(
            kinds.contains(&"tun-device"),
            "network.tun.mtu → tun-device: {kinds:?}"
        );
        assert!(
            preview
                .side_effects
                .iter()
                .all(|s| s.path.starts_with("network")),
            "副作用只来自 network 块: {:?}",
            preview.side_effects
        );
        // 非 network 变更零副作用提示
        let plain = preview_config_patch(
            &cfg,
            &serde_json::json!({"routing": {"default_node": "proxy"}}),
            &full_caps(),
            None,
        );
        assert!(plain.side_effects.is_empty());
    }

    #[test]
    fn scope_violations_flag_out_of_scope_paths() {
        let cfg = base_config();
        let patch = serde_json::json!({
            "routing": {"default_node": "proxy"},
            "control": {"api_bind": "127.0.0.1:9191"}
        });
        let preview =
            preview_config_patch(&cfg, &patch, &full_caps(), Some(&["routing".to_string()]));
        assert!(
            preview
                .scope_violations
                .iter()
                .all(|p| p.starts_with("control")),
            "越界路径只报 control: {:?}",
            preview.scope_violations
        );
        assert!(
            !preview
                .scope_violations
                .iter()
                .any(|p| p.starts_with("routing")),
            "范围内路径不报越界"
        );
        // scope = None → 不报
        let unscoped = preview_config_patch(&cfg, &patch, &full_caps(), None);
        assert!(unscoped.scope_violations.is_empty());
    }

    /// 数组位置对齐：尾部增删按位置报告，索引进路径。
    #[test]
    fn array_diff_is_positional() {
        let cfg = RillaneConfig::from_str(
            "control:\n  api_bind: 127.0.0.1:9090\n  uds_path: null\n  admin_token: null\ntelemetry:\n  log_level: info\n  enable_metrics: false\n  enable_tracing: false\ningress: []\negress:\n  - name: a\n    type: direct\n  - name: b\n    type: direct\nrouting:\n  default_node: direct\n  groups: []\n  rules: []\n",
            Some("yaml"),
        )
        .expect("双出口基线应解析");
        let patch = serde_json::json!({"egress": [{"name": "a", "type": "direct"}]});
        let preview = preview_config_patch(&cfg, &patch, &full_caps(), None);
        assert!(
            preview
                .diff
                .iter()
                .any(|e| e.path == "egress.1" && e.op == DiffOp::Removed),
            "尾元素删除按位置报告: {:?}",
            preview.diff
        );
    }
}
