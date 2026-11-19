//! Windows 生命周期恢复执行面（RIL-035 代码面首段交付）：复用
//! [`super::recovery::CrashJournal`]（同一 JSONL 账本、同一
//! [`plan_for_event`] 映射、同一 [`RecoveryReport`] 形状）——只换载荷
//! 解析器（[`parse_win_step_payload`] 的 route/netsh 形状族）与缺失/
//! 已存在文本谓词（Windows 真机口径）。逐条诚实、不吞错、失败留账
//! 重试，与 Linux 面一处不省。
//!
//! OS-free：执行器可注入、账本落临时目录——Linux 验证席确定性可测；
//! 真机 IO（route.exe/netsh.exe 真执行，经 [`super::win_net::
//! win_step_executor`]）与 SCM 服务生命周期/驱动依赖校验/签名约束
//! （验收「服务崩溃、休眠、切网和卸载不遗留路由/DNS；签名和依赖限制
//! 公开」的真机证据）归机批次——手写从未运行的 FFI/SCM 面不交付
//! （同 RIL-033/034 纪律）。
//!
//! 覆盖语义（与 Linux recover 镜像）：
//! - **逆序撤销**：最新先撤；目标不存在 = 已撤销（幂等）；单条失败
//!   不吞不中断——进 `failed` 且**留账**（下次启动重试），成功条目清掉
//!   → 重复启动无残留；
//! - **文件快照**：当前内容 ≠ 备份才写回（相等 = 已恢复态，幂等跳过
//!   不碰 mtime）；写失败留账；
//! - **切网重放**：[`plan_for_event`] 决策（出口恢复/默认路由变化 →
//!   路由条目幂等重放，EEXIST = 已在位成功；出口丢失/DNS 变化 → 不动
//!   ——撤掉只会制造震荡）；重放**跳过 DNS 劫持形状**（切网时监听
//!   地址可能已随接口变化，DNS 跟随归 DNS 服务面——与 Linux `None`
//!   映射同理，审计如实点名）；
//! - **记账执行器**：执行成功才记账（失败不产生系统变更，无需 undo）；
//!   Windows 形状族之外的 argv 执行成功但不记账（审计 warn 点名）。

use std::io;
use std::path::Path;
use std::sync::Arc;

use tracing::warn;

use super::recovery::{
    plan_for_event, CrashJournal, JournalEntry, NetworkRecoveryAction, RecoveryReport, AUDIT_TARGET,
};
use super::win_takeover::{
    is_eexist, is_missing, parse_win_step_payload, WinAppliedStep, WinStepExecutor,
};
use crate::network::NetworkEvent;

/// 重启修复（Windows 载荷族）：逆序撤销全部待办（最新先撤），收尾
/// 清账。语义与 Linux recover 一致（模块头）。
pub fn recover_windows(
    journal: &CrashJournal,
    exec: &WinStepExecutor,
) -> io::Result<RecoveryReport> {
    let snapshot = journal.pending();
    let mut report = RecoveryReport {
        corrupt_lines_skipped: snapshot.corrupt_lines,
        ..Default::default()
    };
    let mut failed_entries: Vec<JournalEntry> = Vec::new();
    for entry in snapshot.entries.iter().rev() {
        match entry {
            JournalEntry::RouteStep { payload, .. } => {
                let undo = match parse_win_step_payload(payload) {
                    Ok(step) => step.undo_argv(),
                    Err(e) => {
                        report.failed.push(format!("{payload}: 载荷不可解析: {e}"));
                        continue;
                    }
                };
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

/// 记账执行器（Windows 形状族）：包装真实执行器——**执行成功才记账**
/// （undo 载荷解析自 apply 载荷，无第二构造路径）；Windows 形状族之外
/// 的 argv 执行成功但不记账（审计 warn 点名）；记账写盘失败不影响已
/// 成功的系统变更（warn 上报）。
pub fn win_journaling_executor(
    journal: Arc<CrashJournal>,
    inner: WinStepExecutor,
) -> WinStepExecutor {
    Arc::new(move |argv: &[String]| {
        inner(argv)?;
        let payload = argv.join(" ");
        if parse_win_step_payload(&payload).is_ok() {
            if let Err(e) = journal.append_route_step(&payload) {
                warn!(
                    target: AUDIT_TARGET,
                    payload = %payload,
                    error = %e,
                    "崩溃日志写盘失败（系统变更已生效，恢复面缺这一笔）"
                );
            }
        } else {
            warn!(
                target: AUDIT_TARGET,
                payload = %payload,
                "载荷形状族外：执行成功但不入崩溃日志（无 undo 构造路径）"
            );
        }
        Ok(())
    })
}

/// 处理一次网络事件（Windows 载荷族）：按 [`plan_for_event`] 映射执行
/// 恢复动作并返回审计名（`"reassert_routes"` / `"none"`）。路由重放：
/// route 形状幂等重放（EEXIST = 已在位成功）；netsh DNS 劫持形状**不
/// 重放**（切网时监听地址可能已随接口变化——DNS 跟随归 DNS 服务面，
/// 与 Linux `None` 映射同理）；其余失败逐条 warn（不中断）。
pub fn handle_network_event_windows(
    journal: &CrashJournal,
    exec: &WinStepExecutor,
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
                    let parsed = parse_win_step_payload(payload);
                    let argv = match parsed {
                        Ok(step @ WinAppliedStep::RouteAdded { .. }) => step.argv(),
                        Ok(WinAppliedStep::DnsHijack { .. }) => {
                            tracing::info!(
                                target: AUDIT_TARGET,
                                payload = %payload,
                                "DNS 劫持形状不重放（跟随归 DNS 服务面）"
                            );
                            continue;
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Windows 形状族两条合法载荷（include 路由 / DNS 劫持）。
    fn step_route() -> WinAppliedStep {
        WinAppliedStep::RouteAdded {
            destination: "198.18.0.0".into(),
            mask: "255.254.0.0".into(),
            gateway: "192.168.5.1".into(),
            metric: 5,
            interface_index: 12,
        }
    }

    fn step_dns() -> WinAppliedStep {
        WinAppliedStep::DnsHijack {
            interface: "Wi-Fi".into(),
            address: "127.0.0.1".parse().unwrap(),
        }
    }

    fn temp_journal(tag: &str) -> (PathBuf, CrashJournal) {
        let dir = std::env::temp_dir().join(format!(
            "ril035-{}-{}-{}",
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

    fn recording() -> (WinStepExecutor, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let exec: WinStepExecutor = Arc::new(move |argv: &[String]| {
            l.lock().unwrap().push(argv.join(" "));
            Ok(())
        });
        (exec, log)
    }

    fn err(msg: &str) -> io::Error {
        io::Error::other(msg.to_string())
    }

    #[test]
    fn win_recover_undoes_in_reverse_and_reports_honestly() {
        let (_dir, journal) = temp_journal("undo");
        journal
            .append_route_step(&step_route().argv().join(" "))
            .unwrap();
        journal
            .append_route_step(&step_dns().argv().join(" "))
            .unwrap();
        let (exec, log) = recording();
        let report = recover_windows(&journal, &exec).unwrap();
        // 逆序：最新（DNS）先撤
        assert_eq!(report.undone.len(), 2);
        assert_eq!(
            log.lock().unwrap().as_slice(),
            [
                step_dns().undo_argv().join(" "),
                step_route().undo_argv().join(" ")
            ]
        );
        // 全部成功 = 清账（重复启动无残留）
        assert!(journal.pending().entries.is_empty());
        let (exec2, _log2) = recording();
        let again = recover_windows(&journal, &exec2).unwrap();
        assert_eq!(again, RecoveryReport::default());
    }

    #[test]
    fn win_recover_missing_target_is_already_gone_and_failure_retained() {
        let (_dir, journal) = temp_journal("missing");
        journal
            .append_route_step(&step_route().argv().join(" "))
            .unwrap();
        // route delete 未命中 → Windows 真机文本 → 幂等已撤销
        let exec: WinStepExecutor = Arc::new(|argv: &[String]| {
            if argv[0] == "route" && argv[1] == "delete" {
                Err(err(
                    "The route deletion failed: The element could not be found.",
                ))
            } else {
                Ok(())
            }
        });
        let report = recover_windows(&journal, &exec).unwrap();
        assert!(report.undone.is_empty());
        assert_eq!(report.already_gone.len(), 1);
        assert!(report.failed.is_empty());
        assert!(journal.pending().entries.is_empty(), "幂等撤销同样清账");

        // 真失败：留账重试
        let (_d2, j2) = temp_journal("retain");
        j2.append_route_step(&step_route().argv().join(" "))
            .unwrap();
        let exec2: WinStepExecutor = Arc::new(|_: &[String]| Err(err("拒绝执行")));
        let r2 = recover_windows(&j2, &exec2).unwrap();
        assert_eq!(r2.failed.len(), 1);
        assert_eq!(j2.pending().entries.len(), 1, "失败条目留账");
        // 修复后重试成功清账
        let (exec3, _) = recording();
        let r3 = recover_windows(&j2, &exec3).unwrap();
        assert_eq!(r3.undone.len(), 1);
        assert!(j2.pending().entries.is_empty());
    }

    #[test]
    fn win_recover_file_snapshot_skip_equal_and_restore_differs() {
        let (dir, journal) = temp_journal("snapshot");
        let snap_path = dir.join("resolver-state.txt");
        std::fs::write(&snap_path, "hijacked").unwrap();
        journal
            .append_file_snapshot(snap_path.to_str().unwrap(), "original")
            .unwrap();
        let (exec, _) = recording();
        let report = recover_windows(&journal, &exec).unwrap();
        assert_eq!(report.snapshots_restored, 1);
        assert_eq!(std::fs::read_to_string(&snap_path).unwrap(), "original");
        // 内容已等于备份：幂等跳过不误写（再记账模拟第二次接管会话的
        // 快照——与 Linux 面同构；清账语义下成功条目已被首次 recover
        // 清掉，条目须重新存在才有待办）
        journal
            .append_file_snapshot(snap_path.to_str().unwrap(), "original")
            .unwrap();
        let report2 = recover_windows(&journal, &exec).unwrap();
        assert_eq!(report2.snapshots_skipped, 1);
        assert_eq!(report2.snapshots_restored, 0);
        assert_eq!(std::fs::read_to_string(&snap_path).unwrap(), "original");
    }

    #[test]
    fn win_journaling_executor_records_only_win_shapes_on_success() {
        let (dir, journal) = temp_journal("journaling");
        let (inner, _calls) = recording();
        let journalled = win_journaling_executor(Arc::new(journal), inner);
        // Windows 形状成功 → 记账
        journalled(&step_route().argv()).unwrap();
        // 形状族外（Linux ip 载荷）执行成功但不记账（无 undo 构造路径）
        journalled(&["ip".to_string(), "route".to_string(), "replace".to_string()]).unwrap();
        // Windows 形状执行失败 → 不记账（失败不产生系统变更）
        let failing: WinStepExecutor = Arc::new(|_: &[String]| Err(err("拒绝执行")));
        let journalled2 = win_journaling_executor(
            Arc::new(CrashJournal::open(dir.join("crash.jsonl"))),
            failing,
        );
        assert!(journalled2(&step_dns().argv()).is_err());
        // 形状族内仅成功一笔；族外与失败零记账（路径重开 = 生产重启同形）
        let snap = CrashJournal::open(dir.join("crash.jsonl")).pending();
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(
            snap.entries[0],
            JournalEntry::RouteStep {
                seq: 1,
                payload: step_route().argv().join(" ")
            }
        );
    }

    #[test]
    fn win_network_event_reassert_replays_routes_skips_dns_hijack() {
        let (_dir, journal) = temp_journal("reassert");
        journal
            .append_route_step(&step_route().argv().join(" "))
            .unwrap();
        journal
            .append_route_step(&step_dns().argv().join(" "))
            .unwrap();

        // 出口丢失/DNS 变化 → 不动系统态（执行器不该被调到）
        let noop_exec: WinStepExecutor =
            Arc::new(|argv: &[String]| Err(err(&format!("不该执行: {argv:?}"))));
        assert_eq!(
            handle_network_event_windows(&journal, &noop_exec, &NetworkEvent::ConnectivityLost),
            "none"
        );
        assert_eq!(
            handle_network_event_windows(
                &journal,
                &noop_exec,
                &NetworkEvent::DefaultRouteChanged { interface: None }
            ),
            "none"
        );

        // 出口恢复 → 路由条目幂等重放；DNS 劫持形状跳过（跟随归 DNS 面）
        let (exec, log) = recording();
        assert_eq!(
            handle_network_event_windows(&journal, &exec, &NetworkEvent::ConnectivityRestored),
            "reassert_routes"
        );
        assert_eq!(
            log.lock().unwrap().as_slice(),
            [step_route().argv().join(" ")],
            "仅 route 形状重放；netsh 形状不重放"
        );

        // EEXIST = 已在位（成功）
        let eexist_exec: WinStepExecutor =
            Arc::new(|_: &[String]| Err(err("The object already exists.")));
        assert_eq!(
            handle_network_event_windows(
                &journal,
                &eexist_exec,
                &NetworkEvent::DefaultRouteChanged {
                    interface: Some("192.168.6.14".into())
                }
            ),
            "reassert_routes"
        );
    }
}
