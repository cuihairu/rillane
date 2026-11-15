//! Linux 生命周期恢复（RIL-031）：崩溃日志（持久化 JSONL）+ 重启修复
//! + 网络切换恢复动作映射。
//!
//! 与 RIL-018 内存态 [`SideEffectJournal`](crate::network::SideEffectJournal)
//! 的分工：那份是单次运行内的变更账（优雅停机时进程内回滚——runtime
//! stop 已有 TUN teardown 路由回滚/DNS 停服）；本模块管的是**崩溃后**
//! 的残局——进程死了内存账就没了，所以落盘：
//!
//! - **记账**：[`journaling_executor`] 包装路由执行器——**执行成功才
//!   记账**（失败不产生系统变更，无需 undo）；载荷用 RIL-029 的
//!   `step_payload` 形状（「计划=执行」同源，无第二构造路径），恢复
//!   时解析回 `AppliedStep` 走 `undo_argv`。形状族之外的 argv 执行
//!   成功但不记账（审计 warn 点名——记账面只覆盖 RIL-029 形状族）。
//! - **恢复**：[`recover`] 逆序撤销（最新先撤），目标不存在 = 已撤销
//!   （幂等，同 takeover `is_missing` 文本口径）；失败逐条上报不吞、
//!   其余条目继续；`FileSnapshot` 条目当前内容 ≠ 备份才写回（相等 =
//!   已恢复，幂等跳过不碰 mtime）；收尾清账——**重复启动无残留**
//!   （第二次 recover 零待办零动作）。
//! - **切换**：[`handle_network_event`] 把 RIL-029 [`NetworkEvent`]
//!   映射为恢复动作：出口恢复/默认路由变化 → 路由条目幂等重放
//!   （EEXIST 按已存在成功）；连通丢失/DNS 变化 → 不动系统态
//!   （DNS hijack 的跟随归 DNS 服务面，此处撤掉只会制造震荡——审计
//!   如实记 `none`）。崩溃路径的 DNS 恢复由 `FileSnapshot` 承担：
//!   resolv.conf 停在 hijack 态而监听器已死时，启动恢复写回接管前
//!   原文。
//! - **审计**：每笔撤销/恢复/坏账跳过都走 `tracing`（target
//!   `rillane::recovery`）——异常退出日志面。
//!
//! 测试面：日志路径与执行器全部可注入（临时目录 + 记录式闭包），
//! 真实 `ip` 不在测试路径上。

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::network::{parse_step_payload, NetworkEvent, StepExecutor};

/// 审计日志 target（异常退出/恢复动作全部走这里，可按 target 过滤）。
pub const AUDIT_TARGET: &str = "rillane::recovery";

/// 崩溃日志条目（JSONL 逐行一条）。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEntry {
    /// 路由步骤：`payload` 是 RIL-029 AppliedStep 的 argv 空格序列；
    /// 恢复时解析回步骤取 `undo_argv` 逆序执行。
    RouteStep { seq: u64, payload: String },
    /// 文件快照：接管某系统文件（如 resolv.conf）前的原文全文；
    /// 恢复时当前内容 ≠ 备份才写回。
    FileSnapshot {
        seq: u64,
        path: String,
        backup: String,
    },
}

/// 恢复报告（逐条诚实，不吞错）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// 已撤销步骤（undo argv 空格串）
    pub undone: Vec<String>,
    /// 目标本就不存在 = 已撤销（幂等）
    pub already_gone: Vec<String>,
    /// 撤销失败（`"<argv>: <错误>"`）——继续处理其余条目
    pub failed: Vec<String>,
    /// 写回的文件快照数
    pub snapshots_restored: usize,
    /// 内容已等于备份而跳过的快照数（幂等）
    pub snapshots_skipped: usize,
    /// 跳过的坏账行数（审计可见，不当静默丢失）
    pub corrupt_lines_skipped: u32,
}

/// 待办快照：条目 + 坏账行数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSnapshot {
    pub entries: Vec<JournalEntry>,
    pub corrupt_lines: u32,
}

/// 持久化崩溃日志（JSONL；路径注入，真实部署放 /var/lib/rillane 下）。
pub struct CrashJournal {
    path: PathBuf,
}

impl CrashJournal {
    /// 打开（不创建——首笔记账时才落盘）。
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// 日志文件路径（测试重开同一文件用）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读待办：逐行解析，坏行跳过并计数（审计见 [`AUDIT_TARGET`]）。
    pub fn pending(&self) -> JournalSnapshot {
        let mut entries = Vec::new();
        let mut corrupt = 0;
        let Ok(raw) = std::fs::read_to_string(&self.path) else {
            return JournalSnapshot {
                entries,
                corrupt_lines: 0,
            };
        };
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    corrupt += 1;
                    warn!(
                        target: AUDIT_TARGET,
                        line = line.get(..80).unwrap_or(line),
                        error = %e,
                        "崩溃日志坏行跳过（不当静默丢失）"
                    );
                }
            }
        }
        JournalSnapshot {
            entries,
            corrupt_lines: corrupt,
        }
    }

    /// 追加一条（缺父目录则建）；返回序号。
    pub fn append(&self, entry: JournalEntry) -> io::Result<u64> {
        let seq = self.next_seq();
        let mut line_entry = entry;
        match &mut line_entry {
            JournalEntry::RouteStep { seq: s, .. } => *s = seq,
            JournalEntry::FileSnapshot { seq: s, .. } => *s = seq,
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(
            f,
            "{}",
            serde_json::to_string(&line_entry).expect("条目可序列化")
        )?;
        Ok(seq)
    }

    /// 记一笔路由步骤（apply 载荷）。
    pub fn append_route_step(&self, payload: &str) -> io::Result<u64> {
        self.append(JournalEntry::RouteStep {
            seq: 0,
            payload: payload.to_string(),
        })
    }

    /// 记一笔文件快照（原文全文）。
    pub fn append_file_snapshot(&self, path: &str, backup: &str) -> io::Result<u64> {
        self.append(JournalEntry::FileSnapshot {
            seq: 0,
            path: path.to_string(),
            backup: backup.to_string(),
        })
    }

    /// 清账（优雅停机/恢复收尾）：截断为空。
    pub fn clear(&self) -> io::Result<()> {
        std::fs::write(&self.path, b"")
    }

    /// 只保留给定条目（恢复收尾：失败条目留账重试，成功条目清掉）。
    pub fn retain(&self, keep: &[JournalEntry]) -> io::Result<()> {
        if keep.is_empty() {
            return self.clear();
        }
        let mut body = String::new();
        for e in keep {
            body.push_str(&serde_json::to_string(e).expect("条目可序列化"));
            body.push('\n');
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, body)
    }

    /// 下一序号 = 现有条目最大序号 + 1。
    fn next_seq(&self) -> u64 {
        self.pending()
            .entries
            .iter()
            .map(|e| match e {
                JournalEntry::RouteStep { seq, .. } => *seq,
                JournalEntry::FileSnapshot { seq, .. } => *seq,
            })
            .max()
            .unwrap_or(0)
            + 1
    }
}

/// `io::Error` 是否「目标不存在」（同 takeover is_missing 文本口径：
/// ip 输出 "No such..." / "Cannot find device"）。
fn is_missing(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || e.to_string().contains("No such")
        || e.to_string().contains("Cannot find device")
}

/// `io::Error` 是否「目标已存在」（同 takeover is_eexist 文本口径）。
fn is_eexist(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AlreadyExists || e.to_string().contains("File exists")
}

/// 重启修复：逆序撤销全部待办（最新先撤），收尾清账。
/// 单条失败不吞不中断——失败进 `failed` 且**留账**（下次启动重试），
/// 成功条目清掉；全部成功则账清零（重复启动无残留）。
pub fn recover(journal: &CrashJournal, exec: &StepExecutor) -> io::Result<RecoveryReport> {
    let snapshot = journal.pending();
    let mut report = RecoveryReport {
        corrupt_lines_skipped: snapshot.corrupt_lines,
        ..Default::default()
    };
    let mut failed_entries: Vec<JournalEntry> = Vec::new();
    for entry in snapshot.entries.iter().rev() {
        match entry {
            JournalEntry::RouteStep { payload, .. } => {
                let step = match parse_step_payload(payload) {
                    Ok(s) => s,
                    Err(e) => {
                        report.failed.push(format!("{payload}: 载荷不可解析: {e}"));
                        continue;
                    }
                };
                let undo = step.undo_argv();
                match exec(&undo) {
                    Ok(()) => {
                        tracing::info!(target: AUDIT_TARGET, argv = %undo.join(" "), "崩溃残留已撤销");
                        report.undone.push(undo.join(" "));
                    }
                    Err(e) if is_missing(&e) => {
                        tracing::info!(target: AUDIT_TARGET, argv = %undo.join(" "), "目标不存在视为已撤销");
                        report.already_gone.push(undo.join(" "));
                    }
                    Err(e) => {
                        tracing::warn!(target: AUDIT_TARGET, argv = %undo.join(" "), error = %e, "撤销失败");
                        report.failed.push(format!("{}: {e}", undo.join(" ")));
                        failed_entries.push(entry.clone());
                    }
                }
            }
            JournalEntry::FileSnapshot { path, backup, .. } => {
                match std::fs::read_to_string(path) {
                    Ok(current) if current == *backup => {
                        // 内容已等于备份：已恢复态，幂等跳过（不碰 mtime）
                        report.snapshots_skipped += 1;
                    }
                    _ => {
                        if let Some(parent) = Path::new(path).parent() {
                            if std::fs::create_dir_all(parent).is_ok() {
                                // 父目录缺失按需重建；写失败仍如实上报
                            }
                        }
                        match std::fs::write(path, backup) {
                            Ok(()) => {
                                tracing::info!(target: AUDIT_TARGET, path, "系统文件写回接管前原文");
                                report.snapshots_restored += 1;
                            }
                            Err(e) => {
                                tracing::warn!(target: AUDIT_TARGET, path, error = %e, "文件恢复失败");
                                report.failed.push(format!("{path}: {e}"));
                                failed_entries.push(entry.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    // 失败条目留账（下次启动重试），成功条目清掉；全部成功 = 清零
    journal.retain(&failed_entries)?;
    Ok(report)
}

/// 记账执行器：包装真实路由执行器——**执行成功才记账**（undo 载荷
/// 解析自 apply 载荷，无第二构造路径）；形状族之外的 argv 执行成功但
/// 不记账（审计 warn 点名）；记账写盘失败不影响已成功的系统变更
/// （warn 上报）。
pub fn journaling_executor(journal: Arc<CrashJournal>, inner: StepExecutor) -> StepExecutor {
    Arc::new(move |argv: &[String]| {
        inner(argv)?;
        let payload = argv.join(" ");
        match parse_step_payload(&payload) {
            Ok(_) => {
                if let Err(e) = journal.append_route_step(&payload) {
                    warn!(
                        target: AUDIT_TARGET,
                        payload = %payload,
                        error = %e,
                        "崩溃日志写盘失败（系统变更已生效，恢复面缺这一笔）"
                    );
                }
            }
            Err(e) => {
                warn!(
                    target: AUDIT_TARGET,
                    payload = %payload,
                    error = %e,
                    "载荷形状族外：执行成功但不入崩溃日志（无 undo 构造路径）"
                );
            }
        }
        Ok(())
    })
}

/// 网络切换恢复动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkRecoveryAction {
    /// 路由条目幂等重放（apply argv；EEXIST 按已存在成功）
    ReassertRoutes,
    /// 不动系统态（DNS hijack 跟随归 DNS 服务面；审计记 none）
    None,
}

/// 事件 → 动作映射：出口恢复/默认路由切换（有新出口）→ 路由重放；
/// 其余（出口全丢、DNS 变化）→ 不动——撤掉只会制造震荡。
pub fn plan_for_event(event: &NetworkEvent) -> NetworkRecoveryAction {
    match event {
        NetworkEvent::DefaultRouteChanged { interface: Some(_) }
        | NetworkEvent::ConnectivityRestored => NetworkRecoveryAction::ReassertRoutes,
        NetworkEvent::DefaultRouteChanged { interface: None }
        | NetworkEvent::ConnectivityLost
        | NetworkEvent::SystemDnsChanged => NetworkRecoveryAction::None,
    }
}

/// 处理一次网络事件：按映射执行恢复动作并返回审计名
/// （`"reassert_routes"` / `"none"`）。路由重放：EEXIST = 已在位
/// （成功）；其余失败逐条 warn（不中断后续条目）。
pub fn handle_network_event(
    journal: &CrashJournal,
    exec: &StepExecutor,
    event: &NetworkEvent,
) -> &'static str {
    match plan_for_event(event) {
        NetworkRecoveryAction::None => {
            tracing::info!(target: AUDIT_TARGET, event = "none", "事件无需恢复动作");
            "none"
        }
        NetworkRecoveryAction::ReassertRoutes => {
            let snapshot = journal.pending();
            for entry in snapshot.entries.iter().rev() {
                if let JournalEntry::RouteStep { payload, .. } = entry {
                    let step = match parse_step_payload(payload) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                target: AUDIT_TARGET,
                                payload = %payload,
                                error = %e,
                                "重放跳过：载荷不可解析"
                            );
                            continue;
                        }
                    };
                    let argv = step.argv();
                    match exec(&argv) {
                        Ok(()) => {
                            tracing::info!(target: AUDIT_TARGET, argv = %argv.join(" "), "路由条目重放成功");
                        }
                        Err(e) if is_eexist(&e) => {
                            tracing::info!(target: AUDIT_TARGET, argv = %argv.join(" "), "路由条目已在位（EEXIST 按成功）");
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: AUDIT_TARGET,
                                argv = %argv.join(" "),
                                error = %e,
                                "路由重放失败（继续其余条目）"
                            );
                        }
                    }
                }
            }
            "reassert_routes"
        }
    }
}

// —— 单测：临时日志 + 注入执行器，真实 ip 不在测试路径上 ——

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 两条合法 RIL-029 形状载荷（fwmark rule / escape route）。
    const STEP_A: &str = "ip rule add fwmark 24180 table 518";
    const STEP_B: &str = "ip route replace default wg-ril table 518";

    fn temp_journal(tag: &str) -> (PathBuf, CrashJournal) {
        let dir = std::env::temp_dir().join(format!(
            "ril031-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let journal = CrashJournal::open(dir.join("crash.jsonl"));
        (dir, journal)
    }

    fn recording() -> (StepExecutor, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let exec: StepExecutor = Arc::new(move |argv: &[String]| {
            l.lock().unwrap().push(argv.join(" "));
            Ok(())
        });
        (exec, log)
    }

    fn undo_of(payload: &str) -> String {
        parse_step_payload(payload).unwrap().undo_argv().join(" ")
    }

    fn err(msg: &str) -> io::Error {
        io::Error::other(msg.to_string())
    }

    #[test]
    fn append_and_pending_roundtrip_across_reopen() {
        let (_dir, journal) = temp_journal("roundtrip");
        assert_eq!(journal.append_route_step(STEP_A).unwrap(), 1);
        assert_eq!(
            journal
                .append_file_snapshot("/etc/resolv.conf", "nameserver 192.168.5.1\n")
                .unwrap(),
            2
        );
        let snap = journal.pending();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.corrupt_lines, 0);
        assert_eq!(
            snap.entries[0],
            JournalEntry::RouteStep {
                seq: 1,
                payload: STEP_A.into()
            }
        );
        // 跨实例重开（模拟重启）后持久账仍在
        let reopened = CrashJournal::open(journal.path());
        assert_eq!(reopened.pending(), snap);
    }

    #[test]
    fn corrupt_lines_skipped_and_counted() {
        let (dir, journal) = temp_journal("corrupt");
        journal.append_route_step(STEP_A).unwrap();
        // 中途断电写半行 / 手工损坏——坏行跳过并计数，不当静默丢失
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("crash.jsonl"))
            .unwrap();
        writeln!(f, "{{broken json line").unwrap();
        journal.append_route_step(STEP_B).unwrap();
        let snap = journal.pending();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.corrupt_lines, 1);
    }

    #[test]
    fn recover_undoes_in_reverse_order_and_clears() {
        let (_dir, journal) = temp_journal("reverse");
        journal.append_route_step(STEP_A).unwrap();
        journal.append_route_step(STEP_B).unwrap();
        let (exec, log) = recording();
        let report = recover(&journal, &exec).unwrap();
        // 最新先撤
        assert_eq!(*log.lock().unwrap(), vec![undo_of(STEP_B), undo_of(STEP_A)]);
        assert_eq!(report.undone.len(), 2);
        assert!(report.failed.is_empty());
        // 收尾清账：待办归零
        assert!(journal.pending().entries.is_empty());
    }

    #[test]
    fn recover_missing_target_is_already_gone() {
        let (_dir, journal) = temp_journal("gone");
        journal.append_route_step(STEP_A).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let exec: StepExecutor = Arc::new(move |argv: &[String]| {
            l.lock().unwrap().push(argv.join(" "));
            Err(io::Error::from(io::ErrorKind::NotFound))
        });
        let report = recover(&journal, &exec).unwrap();
        assert_eq!(
            report.already_gone,
            vec![undo_of(STEP_A)],
            "目标不存在 = 已撤销（幂等），不算失败"
        );
        assert!(report.failed.is_empty());
        assert!(journal.pending().entries.is_empty());
    }

    #[test]
    fn recover_failure_reported_and_entry_retained_for_retry() {
        let (_dir, journal) = temp_journal("retry");
        journal.append_route_step(STEP_A).unwrap();
        journal.append_route_step(STEP_B).unwrap();
        // 第一条 undo 永久失败，第二条成功——失败不吞不中断
        let exec: StepExecutor = Arc::new(|argv: &[String]| {
            if argv.first().map(|s| s.as_str()) == Some("ip")
                && argv.get(1).map(|s| s.as_str()) == Some("rule")
            {
                Err(err("permission denied"))
            } else {
                Ok(())
            }
        });
        let report = recover(&journal, &exec).unwrap();
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.undone.len(), 1);
        // 失败条目留账，下次启动重试（不静默丢弃残局）
        let leftover = journal.pending();
        assert_eq!(leftover.entries.len(), 1);
        assert_eq!(
            leftover.entries[0],
            JournalEntry::RouteStep {
                seq: 1,
                payload: STEP_A.into()
            }
        );
        // 重试成功后账清零
        let (exec2, _log2) = recording();
        let report2 = recover(&journal, &exec2).unwrap();
        assert_eq!(report2.undone.len(), 1);
        assert!(journal.pending().entries.is_empty());
    }

    #[test]
    fn snapshot_restored_when_differs_and_skipped_when_equal() {
        let (dir, journal) = temp_journal("snapshot");
        let resolv = dir.join("resolv.conf");
        std::fs::write(&resolv, "nameserver 10.66.66.66\n").unwrap(); // hijack 态
        let original = "nameserver 192.168.5.1\n";
        journal
            .append_file_snapshot(resolv.to_str().unwrap(), original)
            .unwrap();
        let (exec, _log) = recording();
        let report = recover(&journal, &exec).unwrap();
        assert_eq!(report.snapshots_restored, 1);
        assert_eq!(std::fs::read_to_string(&resolv).unwrap(), original);
        // 内容已等于备份：幂等跳过不误写
        journal
            .append_file_snapshot(resolv.to_str().unwrap(), original)
            .unwrap();
        let report2 = recover(&journal, &exec).unwrap();
        assert_eq!(report2.snapshots_skipped, 1);
        assert_eq!(report2.snapshots_restored, 0);
        assert_eq!(std::fs::read_to_string(&resolv).unwrap(), original);
    }

    #[test]
    fn repeat_start_leaves_no_residue() {
        let (dir, journal) = temp_journal("residue");
        journal.append_route_step(STEP_A).unwrap();
        journal
            .append_file_snapshot(
                dir.join("resolv.conf").to_str().unwrap(),
                "nameserver 1.1.1.1\n",
            )
            .unwrap();
        let (exec, _log) = recording();
        recover(&journal, &exec).unwrap();
        assert!(journal.pending().entries.is_empty());
        // 第二次启动（重复启动无残留）：零待办零动作
        let report2 = recover(&journal, &exec).unwrap();
        assert_eq!(report2, RecoveryReport::default());
    }

    #[test]
    fn journaling_executor_records_only_on_success() {
        let (_dir, journal) = temp_journal("journaling");
        // 成功 → 记 undo 账
        let ok_exec: StepExecutor = Arc::new(|_: &[String]| Ok(()));
        let j = Arc::new(CrashJournal::open(journal.path()));
        let wrapped = journaling_executor(j.clone(), ok_exec);
        let argv: Vec<String> = STEP_A.split_whitespace().map(String::from).collect();
        wrapped(&argv).unwrap();
        let snap = j.pending();
        assert_eq!(
            snap.entries,
            vec![JournalEntry::RouteStep {
                seq: 1,
                payload: STEP_A.into()
            }]
        );
        // 失败 → 不记账（失败不产生系统变更）
        let fail_exec: StepExecutor = Arc::new(|_: &[String]| Err(err("boom")));
        let wrapped2 = journaling_executor(j.clone(), fail_exec);
        let argv_b: Vec<String> = STEP_B.split_whitespace().map(String::from).collect();
        assert!(wrapped2(&argv_b).is_err());
        assert_eq!(j.pending().entries.len(), 1, "失败不入账");
        // 形状族外：执行成功但不入账（无 undo 构造路径，审计 warn）
        let ok_exec2: StepExecutor = Arc::new(|_: &[String]| Ok(()));
        let wrapped3 = journaling_executor(j.clone(), ok_exec2);
        let foreign: Vec<String> = ["rm", "-rf", "/"].iter().map(|s| s.to_string()).collect();
        wrapped3(&foreign).unwrap();
        assert_eq!(j.pending().entries.len(), 1, "形状族外不入账");
    }

    #[test]
    fn event_mapping_routes_replay_on_restore_only() {
        assert_eq!(
            plan_for_event(&NetworkEvent::ConnectivityRestored),
            NetworkRecoveryAction::ReassertRoutes
        );
        assert_eq!(
            plan_for_event(&NetworkEvent::DefaultRouteChanged {
                interface: Some("wlan0".into())
            }),
            NetworkRecoveryAction::ReassertRoutes
        );
        // 出口全丢 / DNS 变化：不动系统态（hijack 跟随归 DNS 服务面）
        assert_eq!(
            plan_for_event(&NetworkEvent::ConnectivityLost),
            NetworkRecoveryAction::None
        );
        assert_eq!(
            plan_for_event(&NetworkEvent::DefaultRouteChanged { interface: None }),
            NetworkRecoveryAction::None
        );
        assert_eq!(
            plan_for_event(&NetworkEvent::SystemDnsChanged),
            NetworkRecoveryAction::None
        );
    }

    #[test]
    fn reassert_replays_apply_argv_eexist_is_success() {
        let (_dir, journal) = temp_journal("reassert");
        journal.append_route_step(STEP_A).unwrap();
        journal.append_route_step(STEP_B).unwrap();
        // EEXIST 口径：已在位按成功，不报错不中断
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let exec: StepExecutor = Arc::new(move |argv: &[String]| {
            l.lock().unwrap().push(argv.join(" "));
            if argv.first().map(|s| s.as_str()) == Some("ip")
                && argv.get(1).map(|s| s.as_str()) == Some("rule")
            {
                Err(err("RTNETLINK answers: File exists"))
            } else {
                Ok(())
            }
        });
        let action = handle_network_event(&journal, &exec, &NetworkEvent::ConnectivityRestored);
        assert_eq!(action, "reassert_routes");
        // apply argv 重放（非 undo）
        let applied = log.lock().unwrap().clone();
        assert!(applied.contains(&parse_step_payload(STEP_A).unwrap().argv().join(" ")));
        assert!(applied.contains(&parse_step_payload(STEP_B).unwrap().argv().join(" ")));
        // 真失败也不 panic、不中断（继续其余条目）
        let fail_exec: StepExecutor = Arc::new(|_: &[String]| Err(err("no permission")));
        let action2 = handle_network_event(
            &journal,
            &fail_exec,
            &NetworkEvent::DefaultRouteChanged {
                interface: Some("eth1".into()),
            },
        );
        assert_eq!(action2, "reassert_routes");
    }

    #[test]
    fn seq_increases_across_reopen() {
        let (dir, journal) = temp_journal("seq");
        assert_eq!(journal.append_route_step(STEP_A).unwrap(), 1);
        drop(journal);
        let reopened = CrashJournal::open(dir.join("crash.jsonl"));
        assert_eq!(
            reopened.append_route_step(STEP_B).unwrap(),
            2,
            "重开后序号继续递增"
        );
    }

    #[test]
    fn snapshot_write_failure_retains_entry() {
        let (dir, journal) = temp_journal("snapfail");
        // 目标目录是个文件——写回必失败，条目留账
        let blocker = dir.join("blocked.conf");
        std::fs::write(&blocker, "x").unwrap();
        let target = blocker.join("resolv.conf");
        journal
            .append_file_snapshot(target.to_str().unwrap(), "original\n")
            .unwrap();
        let (exec, _log) = recording();
        let report = recover(&journal, &exec).unwrap();
        assert_eq!(report.failed.len(), 1);
        assert_eq!(journal.pending().entries.len(), 1, "失败条目留账");
    }
}
