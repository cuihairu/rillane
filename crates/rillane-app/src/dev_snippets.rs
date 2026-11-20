//! 开发者终端与配置片段预览（RIL-147，纯面）。
//!
//! 口径：为开发者生成本地终端代理环境变量、Git HTTP(S) 代理配置与
//! SSH 走代理配置片段——**复制不修改系统**（缺省只产出文本）；可选
//! 写入限定具体文件/作用域（SSH 管理块写入 `~/.ssh/config` 且先备份、
//! 幂等；Git 走 `git config --global` 两键、不走任意文件改写）。边界
//! （验收原文）：
//! - **SSH 不假定 HTTP_PROXY 生效**：SSH 不读取 HTTP(S)_PROXY 环境变量，
//!   走代理只有 ProxyCommand 一条正道——片段用 `nc -X connect` 经
//!   SOCKS 入口中继；
//! - **工具存在性验证**：SSH 片段依赖 `nc`（netcat-openbsd），Git 片段
//!   依赖 `git`——清单随输出交付，由 CLI 用 PATH 检查填态；
//! - **不改密钥或关 host-key 校验**：生成面只产 ProxyCommand 行——
//!   [`forbidden_ssh_lines`] 审计 `StrictHostKeyChecking`/
//!   `PasswordAuthentication`/`IdentityFile`/`UserKnownHostsFile` 等
//!   键，出现即点名（生成保证 + 测试钉住）；
//! - **不开放任意 shell**：写入面是闭形状——SSH 管理块落
//!   `~/.ssh/config`（备份 `.rillane-bak`），Git 两键经 `git config`
//!   精确 argv，不存在命令透传。

use serde::{Deserialize, Serialize};

/// 管理块标记（幂等判定面：`~/.ssh/config` 已含标记 = 已写入，跳过）
pub const SSH_MANAGED_MARKER: &str = "rillane managed block";

/// SSH 写入的备份文件后缀（恢复 = 把备份拷回原路径）
pub const SSH_BACKUP_SUFFIX: &str = ".rillane-bak";

/// Git 写入的闭键集（仅这两键，无其它作用域）
pub const GIT_CONFIG_KEYS: &[&str] = &["http.proxy", "https.proxy"];

/// 目标 shell（serde 名 snake_case）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevShell {
    Bash,
    Zsh,
    Fish,
    #[serde(rename = "powershell")]
    PowerShell,
    Cmd,
}

impl DevShell {
    /// 终端显示名（清单/文档口径）
    pub fn label(self) -> &'static str {
        match self {
            DevShell::Bash => "bash",
            DevShell::Zsh => "zsh",
            DevShell::Fish => "fish",
            DevShell::PowerShell => "powershell",
            DevShell::Cmd => "cmd",
        }
    }
}

/// 代理端点输入（本地入口 bind 的 host:port 字符串；`http` 供
/// HTTP(S)_PROXY 与 Git，`socks` 供 SSH ProxyCommand）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEndpoints {
    /// HTTP 代理入口（host:port）
    pub http: String,
    /// SOCKS5 代理入口（host:port）
    pub socks: String,
    /// NO_PROXY 例外表
    pub no_proxy: Vec<String>,
}

impl ProxyEndpoints {
    /// 缺省 NO_PROXY 例外（本机回环常量）
    pub fn new(http: impl Into<String>, socks: impl Into<String>) -> Self {
        Self {
            http: http.into(),
            socks: socks.into(),
            no_proxy: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        }
    }
}

/// 终端代理环境变量片段（RIL-147「各平台当前终端变量」）：仅产出文本，
/// 复制不修改系统。变量面 = HTTP_PROXY / HTTPS_PROXY / ALL_PROXY（SOCKS）
/// / NO_PROXY。
pub fn terminal_env_lines(shell: DevShell, ep: &ProxyEndpoints) -> String {
    let all_proxy = format!("socks5://{}", ep.socks);
    let no_proxy = ep.no_proxy.join(",");
    match shell {
        DevShell::Bash | DevShell::Zsh => format!(
            "# 终端代理环境变量（复制到当前会话；不修改系统）\nexport HTTP_PROXY=http://{http}\nexport HTTPS_PROXY=http://{http}\nexport ALL_PROXY={all}\nexport NO_PROXY={no}\n# 取消：unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY\n",
            http = ep.http,
            all = all_proxy,
            no = no_proxy
        ),
        DevShell::Fish => format!(
            "# 终端代理环境变量（复制到当前会话；不修改系统）\nset -x HTTP_PROXY http://{http}\nset -x HTTPS_PROXY http://{http}\nset -x ALL_PROXY {all}\nset -x NO_PROXY {no}\n# 取消：set -e HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY\n",
            http = ep.http,
            all = all_proxy,
            no = no_proxy
        ),
        DevShell::PowerShell => format!(
            "# 终端代理环境变量（复制到当前会话；不修改系统）\n$env:HTTP_PROXY = \"http://{http}\"\n$env:HTTPS_PROXY = \"http://{http}\"\n$env:ALL_PROXY = \"{all}\"\n$env:NO_PROXY = \"{no}\"\n# 取消：Remove-Item Env:HTTP_PROXY, Env:HTTPS_PROXY, Env:ALL_PROXY, Env:NO_PROXY\n",
            http = ep.http,
            all = all_proxy,
            no = no_proxy
        ),
        DevShell::Cmd => format!(
            "rem 终端代理环境变量（复制到当前会话；不修改系统）\nset HTTP_PROXY=http://{http}\nset HTTPS_PROXY=http://{http}\nset ALL_PROXY={all}\nset NO_PROXY={no}\nrem 取消：set HTTP_PROXY= / set HTTPS_PROXY= / set ALL_PROXY= / set NO_PROXY=\n",
            http = ep.http,
            all = all_proxy,
            no = no_proxy
        ),
    }
}

/// Git HTTP(S) 代理配置片段（`git config --global` 两键 + 取消行）。
/// 写入走精确 argv（见 rillanectl `dev-env --apply-git`），无任意命令面。
pub fn git_config_lines(ep: &ProxyEndpoints) -> Vec<String> {
    vec![
        "# Git 走代理（两键；取消：git config --global --unset <键>）".to_string(),
        format!("git config --global http.proxy http://{}", ep.http),
        format!("git config --global https.proxy http://{}", ep.http),
    ]
}

/// SSH 走代理配置块（RIL-147）：**SSH 不读取 HTTP(S)_PROXY 环境变量**——
/// 唯一支持的中继是 ProxyCommand；块内只有 ProxyCommand 一条配置，不碰
/// 密钥/host-key 校验（`forbidden_ssh_lines` 审计为空是生成保证）。
pub fn ssh_config_block(hosts: &[&str], ep: &ProxyEndpoints) -> String {
    let host_list = if hosts.is_empty() {
        "github.com gitlab.com".to_string()
    } else {
        hosts.join(" ")
    };
    format!(
        "# {marker}（RIL-147）：SSH 不读取 HTTP(S)_PROXY 环境变量，走代理仅 ProxyCommand 生效；\n# 本块不改密钥、不关 host-key 校验；依赖 nc（netcat-openbsd）。移除：删除本块（备份 {suffix} 可恢复）。\nHost {hosts}\n    ProxyCommand nc -X connect -x {socks} %h %p\n",
        marker = SSH_MANAGED_MARKER,
        suffix = SSH_BACKUP_SUFFIX,
        hosts = host_list,
        socks = ep.socks,
    )
}

/// 禁用键审计（RIL-147「不改密钥或关 host-key 校验」）：扫描生成/写入
/// 内容，返回含禁用键的行（生成保证为空；写入前复核）。
pub fn forbidden_ssh_lines(content: &str) -> Vec<String> {
    const FORBIDDEN: &[&str] = &[
        "StrictHostKeyChecking",
        "UserKnownHostsFile",
        "PasswordAuthentication",
        "IdentityFile",
        "IdentityAgent",
        "PubkeyAuthentication",
    ];
    content
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            FORBIDDEN
                .iter()
                .any(|k| t.starts_with(k) || t.starts_with(&format!("# {}", k)))
        })
        .map(|s| s.to_string())
        .collect()
}

/// 配置 diff 预览（RIL-147「复制与 diff」）：current = 当前内容（None =
/// 文件不存在），desired = 期望内容。返回逐行 `-`/`+`（行集合差；顺序
/// 保持 desired 在前）。无差异 = 空（幂等口径）。
pub fn diff_preview(current: Option<&str>, desired: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(cur) = current else {
        for line in desired.lines() {
            out.push(format!("+ {line}"));
        }
        return out;
    };
    let cur: Vec<&str> = cur.lines().collect();
    let des: Vec<&str> = desired.lines().collect();
    for line in &des {
        if !cur.contains(line) {
            out.push(format!("+ {line}"));
        }
    }
    for line in &cur {
        if !des.contains(line) {
            out.push(format!("- {line}"));
        }
    }
    out
}

/// SSH 写入计划（RIL-147「写入需授权/备份/幂等/冲突/恢复」）：授权 =
/// CLI 显式 `--write-ssh`；幂等 = 已含管理块标记 → 跳过；冲突 =
/// 备份已在场（CLI 拒写并提示先恢复/移除）；恢复 = 备份拷回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshWritePlan {
    /// 目标文件路径
    pub path: String,
    /// 备份路径（`<path>{SSH_BACKUP_SUFFIX}`）
    pub backup_path: String,
    /// 已含管理块 = 幂等跳过
    pub idempotent: bool,
    /// 追加内容
    pub snippet: String,
}

/// 生成写入计划（纯面——实际落盘在 CLI，须先过 [`forbidden_ssh_lines`]）。
pub fn plan_ssh_write(path: &str, current: Option<&str>, snippet: &str) -> SshWritePlan {
    SshWritePlan {
        path: path.to_string(),
        backup_path: format!("{path}{SSH_BACKUP_SUFFIX}"),
        idempotent: current.is_some_and(|c| c.contains(SSH_MANAGED_MARKER)),
        snippet: snippet.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> ProxyEndpoints {
        ProxyEndpoints::new("127.0.0.1:7890", "127.0.0.1:7890")
    }

    /// 终端变量：各 shell 语法正确、四变量齐全、SOCKS 面 ALL_PROXY
    #[test]
    fn terminal_env_per_shell() {
        let cases = [
            (DevShell::Bash, "export HTTP_PROXY=http://127.0.0.1:7890"),
            (DevShell::Zsh, "export HTTP_PROXY=http://127.0.0.1:7890"),
            (DevShell::Fish, "set -x HTTP_PROXY http://127.0.0.1:7890"),
            (
                DevShell::PowerShell,
                "$env:HTTP_PROXY = \"http://127.0.0.1:7890\"",
            ),
            (DevShell::Cmd, "set HTTP_PROXY=http://127.0.0.1:7890"),
        ];
        for (shell, expect) in cases {
            let out = terminal_env_lines(shell, &ep());
            assert!(out.contains(expect), "{} 缺行: {}", shell.label(), out);
            assert!(out.contains("ALL_PROXY"), "{} 缺 ALL_PROXY", shell.label());
            assert!(out.contains("NO_PROXY"), "{} 缺 NO_PROXY", shell.label());
            assert!(
                out.contains("socks5://127.0.0.1:7890"),
                "{} ALL_PROXY 走 SOCKS 面: {}",
                shell.label(),
                out
            );
            assert!(
                out.contains("不修改系统"),
                "{} 带不动系统说明",
                shell.label()
            );
        }
    }

    /// Git 片段：闭键集两行 + 取消说明
    #[test]
    fn git_lines_are_two_scoped_keys() {
        let lines = git_config_lines(&ep());
        assert_eq!(lines.len(), 3, "说明 + 两键: {:?}", lines);
        let joined = lines.join("\n");
        for key in GIT_CONFIG_KEYS {
            assert!(
                joined.contains(&format!("git config --global {key} http://127.0.0.1:7890")),
                "键 {key} 行在场: {joined}"
            );
        }
        assert!(joined.contains("--unset"));
    }

    /// SSH 块：ProxyCommand 走 SOCKS、不假定 HTTP_PROXY、禁用键审计为空
    #[test]
    fn ssh_block_uses_proxy_command_only() {
        let block = ssh_config_block(&["github.com", "gitlab.com"], &ep());
        assert!(block.contains(SSH_MANAGED_MARKER));
        assert!(block.contains("ProxyCommand nc -X connect -x 127.0.0.1:7890 %h %p"));
        assert!(block.contains("Host github.com gitlab.com"));
        assert!(
            block.contains("不读取 HTTP(S)_PROXY"),
            "点名 SSH 不假定 HTTP_PROXY 生效"
        );
        assert!(
            block.contains("不改密钥、不关 host-key 校验"),
            "边界说明在场"
        );
        assert!(
            forbidden_ssh_lines(&block).is_empty(),
            "生成块禁用键审计必须为空: {:?}",
            forbidden_ssh_lines(&block)
        );
        // 空主机表 → 缺省样例主机
        let default = ssh_config_block(&[], &ep());
        assert!(default.contains("Host github.com gitlab.com"));
    }

    /// 禁用键审计：注入坏行即点名
    #[test]
    fn forbidden_audit_catches_bad_keys() {
        let bad = "Host x\n    StrictHostKeyChecking no\n    PasswordAuthentication yes\n    IdentityFile ~/.ssh/id_ed25519\n";
        let hits = forbidden_ssh_lines(bad);
        assert_eq!(hits.len(), 3, "三坏行全点名: {:?}", hits);
        assert!(hits
            .iter()
            .all(|h| h.contains("no") || h.contains("yes") || h.contains("id_ed25519")));
    }

    /// diff 预览：新建/更新/幂等三态
    #[test]
    fn diff_preview_three_states() {
        let desired = "Host a\n    ProxyCommand x\n";
        // 新建（current None）→ 全 +
        let d = diff_preview(None, desired);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|l| l.starts_with("+ ")));
        // 幂等（内容一致）→ 空
        assert!(
            diff_preview(Some(desired), desired).is_empty(),
            "无差异为空"
        );
        // 更新 → ± 并存
        let cur = "Host a\n    ProxyCommand old\n";
        let d = diff_preview(Some(cur), desired);
        assert!(d.iter().any(|l| l.contains("ProxyCommand x")));
        assert!(d.iter().any(|l| l.contains("ProxyCommand old")));
    }

    /// 写入计划：备份命名、幂等标记判定
    #[test]
    fn write_plan_backup_and_idempotency() {
        let snippet = ssh_config_block(&["github.com"], &ep());
        let plan = plan_ssh_write("/home/u/.ssh/config", None, &snippet);
        assert_eq!(plan.backup_path, "/home/u/.ssh/config.rillane-bak");
        assert!(!plan.idempotent, "无管理块 = 非幂等（将写入）");

        let cur = format!("Host other\n    User x\n\n{snippet}");
        let plan = plan_ssh_write("/home/u/.ssh/config", Some(&cur), &snippet);
        assert!(plan.idempotent, "已含管理块标记 = 幂等跳过");
    }

    /// serde：shell 名 snake_case 往返
    #[test]
    fn shell_serde_snake_case() {
        let s = serde_json::to_string(&DevShell::PowerShell).expect("可序列化");
        assert_eq!(s, "\"powershell\"");
        let back: DevShell = serde_json::from_str(&s).expect("回读");
        assert_eq!(back, DevShell::PowerShell);
    }
}
