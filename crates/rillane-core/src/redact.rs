//! DiagnosticView 脱敏边界（RIL-057，debug-and-mcp.md §4/§6）：CLI/UI/
//! MCP 统一输出的字段白名单与脱敏契约。
//!
//! 设计口径落点（debug-and-mcp.md §6）：
//! - **结构化字段白名单**：诊断视图的每一列都必须经
//!   [`Redactor`] 的具名方法产出——没有"附加任意字符串"的后门，
//!   原始 `diagnose` 压缩包没有对应入口（**没有字段可填就没有东西
//!   可泄**）；
//! - **两档范围**：[`RedactionScope::Aliases`]（默认导出——域名/路径/
//!   节点地址/端点全部稳定别名替代）与 [`RedactionScope::Detailed`]
//!   （本机详细查看——身份字段按原值呈现，**需单独授权**）；
//! - **秘密永远不出边界**：订阅 URL、密码、私钥、token、原始运行
//!   配置在**两档范围内都**被剥除/替代——详细授权放大的是身份字段
//!   （域名/路径/地址可见），不是秘密（§6「订阅 URL、密码、私钥、
//!   token、原始运行配置默认不出边界」）；
//! - **日志/名称按不可信文本处理**（§6「订阅名称、日志、注释是
//!   **不可信数据**，不能变成工具指令」）：控制字符与零宽字符消毒、
//!   长度截断——两档范围都过这一关；
//! - **别名稳定可复现**：同一输入在同一 [`Redactor`] 内得到同一别名
//!   （计数器 + 去重表，内核不引入随机源）——轨迹对照与回归测试
//!   可复现。

use std::collections::HashMap;

/// 脱敏范围：导出默认用 [`RedactionScope::Aliases`]；本机详细查看用
/// [`RedactionScope::Detailed`]（需单独权限——授权决策在调用方，本模块
/// 只保证两档下秘密都不出边界）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionScope {
    /// 默认导出：域名/路径/节点地址/端点全部稳定别名替代
    Aliases,
    /// 本机详细：身份字段按原值（秘密仍然剥除）
    Detailed,
}

impl RedactionScope {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            RedactionScope::Aliases => "aliases",
            RedactionScope::Detailed => "detailed",
        }
    }
}

/// 脱敏器：每份导出视图装配一个（别名表随视图生命周期，跨视图不
/// 关联）。所有输出列都经具名方法产出——白名单由方法集合构成。
/// 范围必须显式选择（无 Default——静默选档本身就是脱敏事故）。
#[derive(Debug)]
pub struct Redactor {
    scope: RedactionScope,
    aliases: HashMap<String, String>,
    counter: usize,
}

const DEFAULT_MAX_TEXT: usize = 512;

impl Redactor {
    /// 按范围装配
    pub fn new(scope: RedactionScope) -> Self {
        Redactor {
            scope,
            aliases: HashMap::new(),
            counter: 0,
        }
    }

    /// 当前范围
    pub fn scope(&self) -> RedactionScope {
        self.scope
    }

    /// 下一个稳定别名（同一输入同一别名——去重表保证）
    fn alias(&mut self, kind: &str, raw: &str) -> String {
        if let Some(existing) = self.aliases.get(raw) {
            return existing.clone();
        }
        self.counter += 1;
        let alias = format!("{kind}-{}", self.counter);
        self.aliases.insert(raw.to_string(), alias.clone());
        alias
    }

    /// 端点（host:port）：Aliases 档稳定别名（端口保留——拓扑语义），
    /// Detailed 档原值
    pub fn endpoint(&mut self, host: &str, port: u16) -> String {
        match self.scope {
            RedactionScope::Aliases => format!("{}:{port}", self.alias("ep", host)),
            RedactionScope::Detailed => format!("{host}:{port}"),
        }
    }

    /// 域名：Aliases 档稳定别名，Detailed 档原值
    pub fn domain(&mut self, domain: &str) -> String {
        match self.scope {
            RedactionScope::Aliases => self.alias("domain", domain),
            RedactionScope::Detailed => domain.to_string(),
        }
    }

    /// 应用路径：Aliases 档稳定别名（路径含用户名/应用指纹），Detailed
    /// 档原值
    pub fn path(&mut self, path: &str) -> String {
        match self.scope {
            RedactionScope::Aliases => self.alias("path", path),
            RedactionScope::Detailed => path.to_string(),
        }
    }

    /// 节点名：订阅文本——**不可信数据**，两档都先消毒；Aliases 档再
    /// 别名替代（订阅节点名可含机场内部拓扑与备注）
    pub fn node(&mut self, node_name: &str) -> String {
        let clean = sanitize_untrusted(node_name, DEFAULT_MAX_TEXT);
        match self.scope {
            RedactionScope::Aliases => self.alias("node", &clean),
            RedactionScope::Detailed => clean,
        }
    }

    /// URL：秘密剥除在两档都执行——userinfo 凭证、查询串中的
    /// token/password/secret/key/sign 类参数整体移除；Aliases 档再整体
    /// 别名替代（订阅 URL 不出边界）
    pub fn url(&mut self, url: &str) -> String {
        let stripped = strip_url_secrets(url);
        match self.scope {
            RedactionScope::Aliases => self.alias("url", &stripped),
            RedactionScope::Detailed => stripped,
        }
    }

    /// 错误消息：私钥块整体剥除、key=value 秘密对剥除在两档都执行；
    /// 消息本体按不可信文本消毒并截断
    pub fn error_message(&mut self, message: &str) -> String {
        let no_keys = strip_pem(&strip_secret_pairs(message));
        sanitize_untrusted(&no_keys, DEFAULT_MAX_TEXT)
    }

    /// 二进制/配置文本块：永远只出标签与字节数——原始运行配置没有
    /// 出边界的形式（§6「原始运行配置默认不出边界」）
    pub fn blob(&self, label: &str, bytes: &[u8]) -> String {
        format!("{} ({} bytes)", sanitize_untrusted(label, 64), bytes.len())
    }

    /// 已脱敏的自由文本列：两档都消毒 + 截断（调用方已脱敏的上下文
    /// 也要过这道闸——边界统一，不信任上游纪律）
    pub fn text(&self, value: &str) -> String {
        sanitize_untrusted(value, DEFAULT_MAX_TEXT)
    }
}

/// 不可信文本消毒（两档范围都执行）：移除零宽/不可见字符、控制字符
/// 换成占位符、长度截断——日志/订阅名称/注释不能变成工具指令或
/// 终端转义序列
pub fn sanitize_untrusted(text: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_len));
    for ch in text.chars() {
        if is_invisible(ch) {
            continue;
        }
        if ch.is_control() {
            out.push('\u{FFFD}');
            continue;
        }
        if out.len() + ch.len_utf8() > max_len {
            break;
        }
        out.push(ch);
    }
    out
}

fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{2060}' // WORD JOINER
        | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE
        | '\u{00AD}' // SOFT HYPHEN
    )
}

/// 剥除 URL 秘密：userinfo 凭证（`user:pass@`）与查询串中
/// token/password/secret/key/sign 类参数整体移除；其余结构保留
/// （Detailed 档还需要 URL 可读——剥的只是凭证）
fn strip_url_secrets(url: &str) -> String {
    // userinfo：scheme://user:pass@host → scheme://host
    let (head, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let rest = match rest.split_once('@') {
        Some((_userinfo, host_part)) if !host_part.starts_with('/') => host_part.to_string(),
        _ => rest.to_string(),
    };
    // 查询串：逐参数过滤秘密键
    let (before_query, query) = match rest.split_once('?') {
        Some((base, q)) => (base.to_string(), Some(q)),
        None => (rest, None),
    };
    let mut out = head;
    out.push_str(&before_query);
    if let Some(query) = query {
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
                !matches!(
                    key.as_str(),
                    "token"
                        | "password"
                        | "passwd"
                        | "pwd"
                        | "secret"
                        | "key"
                        | "sign"
                        | "signature"
                        | "auth"
                        | "credential"
                        | "api_key"
                        | "apikey"
                )
            })
            .collect();
        if !kept.is_empty() {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
    }
    out
}

/// 剥除 PEM 私钥块（-----BEGIN ... PRIVATE KEY----- 到 -----END ...）：
/// 密钥材料整体替换为占位符
fn strip_pem(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") && trimmed.contains("PRIVATE KEY") {
            in_block = true;
            out.push_str("[private key removed]\n");
            continue;
        }
        if in_block {
            if trimmed.starts_with("-----END") {
                in_block = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // lines() 丢失末尾换行语义：去掉补加的最后一个换行
    if !text.ends_with('\n') {
        while out.ends_with('\n') {
            out.pop();
        }
    }
    out
}

/// 剥除 key=value 形态的密码/token（password=xxx / token: xxx）：
/// 值整体替换为占位符，键保留（错误上下文仍可读）
fn strip_secret_pairs(text: &str) -> String {
    const SECRET_KEYS: [&str; 8] = [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "credential",
    ];
    let mut out = text.to_string();
    for key in SECRET_KEYS {
        for sep in ['=', ':'] {
            let needle = format!("{key}{sep}");
            while let Some(pos) = out.to_ascii_lowercase().find(&needle) {
                // 跳过分隔后的前导空白（"token: xxx" 形态——值不在紧邻处）
                let bytes = out.as_bytes();
                let mut value_start = pos + needle.len();
                while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
                    value_start += 1;
                }
                let value_end = out[value_start..]
                    .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"')
                    .map(|i| value_start + i)
                    .unwrap_or(out.len());
                out.replace_range(pos..value_end, "[secret removed]");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 范围机器口径恒定
    #[test]
    fn scope_machine_codes_are_stable() {
        assert_eq!(RedactionScope::Aliases.as_str(), "aliases");
        assert_eq!(RedactionScope::Detailed.as_str(), "detailed");
    }

    /// 别名稳定可复现：同输入同别名、异输入异别名、跨方法不串号
    #[test]
    fn aliases_are_stable_and_distinct() {
        let mut redactor = Redactor::new(RedactionScope::Aliases);
        let a1 = redactor.endpoint("9.9.9.9", 443);
        let a2 = redactor.endpoint("9.9.9.9", 443);
        let b1 = redactor.endpoint("10.0.0.1", 443);
        assert_eq!(a1, a2, "同一端点同别名（轨迹对照可复现）");
        assert_ne!(a1, b1);
        assert!(a1.ends_with(":443"), "端口保留（拓扑语义）");
        let d1 = redactor.domain("example.com");
        let d2 = redactor.domain("example.com");
        assert_eq!(d1, d2);
        assert_ne!(d1, a1, "域名与端点别名空间独立可辨");
        assert!(redactor.domain("other.com").starts_with("domain-"));
        // 序号全局递增：同视图内第 k 个新身份拿 k 号（跨类别共享计数）
    }

    /// Aliases 档身份全替代；Detailed 档身份原值——授权放大的是身份
    #[test]
    fn detailed_scope_keeps_identity_fields() {
        let mut aliases = Redactor::new(RedactionScope::Aliases);
        assert!(aliases.domain("example.com").starts_with("domain-"));
        assert!(aliases.path("/usr/bin/app").starts_with("path-"));
        assert_eq!(aliases.endpoint("1.2.3.4", 80), "ep-3:80", "序号全局递增");

        let mut detailed = Redactor::new(RedactionScope::Detailed);
        assert_eq!(detailed.domain("example.com"), "example.com");
        assert_eq!(detailed.path("/usr/bin/app"), "/usr/bin/app");
        assert_eq!(detailed.endpoint("1.2.3.4", 80), "1.2.3.4:80");
    }

    /// 订阅 URL 不出边界：token/password 查询参数与 userinfo 凭证两档
    /// 都剥除；Aliases 档整体别名替代
    #[test]
    fn url_secrets_stripped_in_both_scopes() {
        let sub = "https://user:pass@example.com/sub?token=abc123&flag=1";
        let mut aliases = Redactor::new(RedactionScope::Aliases);
        let out = aliases.url(sub);
        assert!(!out.contains("token"), "Aliases 档 URL 整体替代：{out}");
        assert!(!out.contains("abc123"));
        assert!(!out.contains("pass"));

        let mut detailed = Redactor::new(RedactionScope::Detailed);
        let out = detailed.url(sub);
        assert_eq!(
            out, "https://example.com/sub?flag=1",
            "Detailed 档剥凭证保留结构"
        );
        assert!(!out.contains("abc123") && !out.contains("pass"));

        // 多种秘密键名全覆盖
        let mut r = Redactor::new(RedactionScope::Detailed);
        let out = r.url("https://h/p?api_key=k&secret=s&sign=x&keep=y&password=p");
        assert_eq!(
            out, "https://h/p?keep=y",
            "api_key/secret/sign/password 全剥除"
        );
    }

    /// 私钥与密码不出边界：PEM 块整体剥除、key=value 秘密对剥除
    #[test]
    fn private_key_and_password_never_exit() {
        let mut r = Redactor::new(RedactionScope::Detailed);
        let msg = "handshake failed\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\nretry later";
        let out = r.error_message(msg);
        assert!(
            out.contains("[private key removed]"),
            "PEM 块整体替换：{out}"
        );
        assert!(!out.contains("MIIEow"), "密钥材料不出边界");
        assert!(out.contains("retry later"), "非密钥上下文保留");

        let out = r.error_message("auth failed password=hunter2 or token: eyJabc def");
        assert!(!out.contains("hunter2"), "password= 值剥除：{out}");
        assert!(!out.contains("eyJabc"), "token: 值剥除");
        assert!(out.contains("[secret removed]"));
        assert!(out.contains("auth failed"), "键外上下文保留");
    }

    /// 原始运行配置没有出边界的形式：blob 只出标签与字节数
    #[test]
    fn raw_config_blob_never_exits() {
        let r = Redactor::new(RedactionScope::Detailed);
        let config = b"proxies:\n  - password: super-secret\n";
        let out = r.blob("runtime_config", config);
        assert_eq!(out, "runtime_config (36 bytes)");
        assert!(!out.contains("super-secret"));
    }

    /// 日志/名称按不可信文本处理：零宽字符移除、控制字符占位、长度
    /// 截断——两档一致
    #[test]
    fn untrusted_text_sanitized_in_both_scopes() {
        let dirty = "机场\u{200B}备注\u{7}title!";
        let mut aliases = Redactor::new(RedactionScope::Aliases);
        let out = aliases.node(dirty);
        assert!(!out.contains('\u{200B}'), "零宽字符移除");
        assert!(!out.contains('\u{7}'), "控制字符占位/移除");
        assert_eq!(aliases.node(dirty), out, "消毒后同输入同别名");

        let mut detailed = Redactor::new(RedactionScope::Detailed);
        let out = detailed.node(dirty);
        assert!(!out.contains('\u{200B}') && !out.contains('\u{7}'));

        // 长度截断
        let long = "x".repeat(10_000);
        assert!(detailed.text(&long).len() <= DEFAULT_MAX_TEXT);
        // 两档都过消毒闸（text 入口与范围无关）
        assert!(!detailed.text("a\u{200D}b").contains('\u{200D}'));
        assert!(!aliases.text("a\u{200D}b").contains('\u{200D}'));
    }

    /// 白名单结构性：Redactor 没有任何"附加原始字符串"入口——自由
    /// 文本也必须过消毒（编译期即无后门：方法集合就是白名单）
    #[test]
    fn whitelist_is_the_method_set() {
        let mut r = Redactor::new(RedactionScope::Aliases);
        // 已"脱敏"的自由文本列同样过闸（不信任上游纪律）
        let out = r.text("delay=42ms node=机场-A\u{200B}");
        assert_eq!(out, "delay=42ms node=机场-A");
        // blob/text/error_message 输出不进入别名表（别名只给身份字段）
        let before = r.domain("a.com");
        let _ = r.error_message("domain a.com password=x");
        let after = r.domain("a.com");
        assert_eq!(before, after, "非身份入口不消耗别名序号");
    }
}
