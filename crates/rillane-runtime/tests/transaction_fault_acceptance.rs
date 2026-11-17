//! 事务与故障注入验收（RIL-088 / RIL-019 发布协调器 × RIL-023 安全撤销）：
//! 逐阶段失败（prepare/apply/提交后记账）与磁盘错误不留半态——重开即
//! 一致（journal 是唯一权威）；apply 失败（网络失联面）旧代际保留、
//! 修复后同候选补偿重放成功；真实子进程崩溃（SIGABRT）在提交点前的
//! Prepared/Applied 挂起一律回滚、recover 幂等可重放；提交点之后、
//! drain 记账之前的崩溃——成功回执（effective）保留，但未补偿的旧代
//! 际目录以孤儿可见（不用成功回执掩盖），reclaim 收敛；会话排空先于
//! 代际回收（retained 面驱动 drain，drain 完才 reclaim）；多客户端并
//! 发读永不见撕裂 journal（原子 rename 提交点）。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use rillane_config::{GenerationObject, ObjectId, ObjectKind, RuntimeGeneration, SourceId};
use rillane_core::plan::EndpointRef;
use rillane_core::resources::{LeaseGuard, LeaseKey, PoolResourceKind};
use rillane_runtime::{
    EffectiveEntry, PendingTx, PublishCoordinator, PublishError, PublishJournal, PublishPhase,
    CODE_GENERATION_UNCHANGED, CODE_JOURNAL_CORRUPT,
};

// ---------------------------------------------------------------------------
// 助手
// ---------------------------------------------------------------------------

/// 独立临时状态目录（进程级唯一——子进程崩溃模拟互不串扰）
fn temp_state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rillane-txn-fault-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("临时目录");
    dir
}

/// 构造含一个节点对象的代际；tag 进内容摘要——不同 tag 必不同代际
fn mk_gen(tag: &str) -> RuntimeGeneration {
    let source = SourceId::new("local").expect("合法 SourceId");
    RuntimeGeneration::build(
        vec![GenerationObject {
            id: ObjectId::new(source, "n1"),
            kind: ObjectKind::Node,
            content_hash: format!("hash-{tag}"),
        }],
        vec![],
    )
    .expect("合法代际")
}

/// 直写 journal（模拟「进程已死、磁盘定格」——崩溃注入面：协调器私有
/// 面不可达，磁盘字节才是崩溃现场）
fn write_journal_raw(dir: &Path, journal: &PublishJournal) {
    let path = dir.join("publish-journal.json");
    let tmp = path.with_extension("json.tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(journal).expect("journal 可序列化"),
    )
    .expect("临时 journal 写入");
    fs::rename(&tmp, &path).expect("journal 原子替换");
}

/// 子进程崩溃体：按指定阶段定格磁盘状态后 SIGABRT（真实崩溃——不是
/// 返回 Err 模拟）。只在 RIL088_CHILD 注入时执行。
fn crash_child(phase: &str, dir: &Path) {
    let g1 = mk_gen("v1");
    let g2 = mk_gen("v2");
    // 暂存目录已落（prepare 段产物）
    let staged = dir.join("generations").join(g2.generation_id());
    fs::create_dir_all(&staged).expect("子进程暂存目录");
    fs::write(staged.join("generation.json"), "candidate").expect("暂存内容");
    // journal 定格：effective = g1（已提交的旧现役）；pending 按注入阶段
    let journal = PublishJournal {
        effective: Some(EffectiveEntry {
            generation_id: g1.generation_id().to_string(),
            published_at_epoch: 0,
        }),
        pending: Some(PendingTx {
            generation_id: g2.generation_id().to_string(),
            phase: if phase == "applied" {
                PublishPhase::Applied
            } else {
                PublishPhase::Prepared
            },
            started_at_epoch: 0,
        }),
        retained: vec![],
    };
    write_journal_raw(dir, &journal);
    std::process::abort();
}

// ---------------------------------------------------------------------------
// 契约测试
// ---------------------------------------------------------------------------

/// 逐阶段失败与补偿重放：prepare 段暂存失败 → Err、旧代际保留、无
/// 挂起；apply 段失败（网络失联面：出口应用不可达）→ ApplyFailed、
/// 旧代际保留、失败候选暂存清掉；故障排除后同候选重放成功；同代际
/// 空转提交拒绝。
#[test]
fn phase_failures_preserve_state_and_replay() {
    let dir = temp_state_dir("phase-fail");
    let mut coord = PublishCoordinator::open(&dir).expect("open");
    let g1 = mk_gen("v1");
    coord.transact(&g1, |_| Ok(())).expect("首次发布");
    let g2 = mk_gen("v2");
    let g3 = mk_gen("v3");

    // prepare 段失败：暂存路径被文件占位 → create_dir_all 失败
    let gens_root = dir.join("generations");
    fs::create_dir_all(&gens_root).expect("generations 根目录");
    let sabotage = gens_root.join(g2.generation_id());
    fs::write(&sabotage, "not-a-dir").expect("占位文件");
    let err = coord
        .transact(&g2, |_| Ok(()))
        .expect_err("prepare 失败须上抛");
    let PublishError::JournalCorrupt { detail } = &err else {
        panic!("prepare 失败应为 JournalCorrupt: {err:?}");
    };
    assert!(detail.contains("暂存失败"), "失败点可解释: {detail}");
    assert_eq!(coord.effective(), Some(g1.generation_id()), "旧代际保留");

    // 重开即一致：磁盘权威无半态（pending 不存在——prepare 未过账）
    let reread = PublishCoordinator::open(&dir).expect("重开");
    assert_eq!(reread.effective(), Some(g1.generation_id()));
    assert!(reread.journal().pending.is_none(), "prepare 失败无挂起残留");

    // 补偿重放：故障排除后同候选成功
    fs::remove_file(&sabotage).expect("排除故障");
    let outcome = coord.transact(&g2, |_| Ok(())).expect("重放成功");
    assert_eq!(outcome.published, g2.generation_id());
    assert_eq!(coord.effective(), Some(g2.generation_id()));

    // apply 段失败（网络失联面）：出口应用不可达 → 旧代际保留、暂存清掉
    let err = coord
        .transact(&g3, |_| {
            Err("network unreachable: 出口规则下发超时".to_string())
        })
        .expect_err("apply 失败须上抛");
    let PublishError::ApplyFailed(reason) = &err else {
        panic!("apply 失败应为 ApplyFailed: {err:?}");
    };
    assert!(reason.contains("network unreachable"), "原因透传: {reason}");
    assert_eq!(coord.effective(), Some(g2.generation_id()), "旧代际保留");
    assert!(
        !dir.join("generations").join(g3.generation_id()).exists(),
        "失败候选暂存清掉"
    );
    let reread = PublishCoordinator::open(&dir).expect("重开");
    assert!(reread.journal().pending.is_none(), "apply 失败无挂起");

    // 补偿重放：网络恢复后同候选成功
    let outcome = coord.transact(&g3, |_| Ok(())).expect("网络恢复后重放");
    assert_eq!(outcome.previous, Some(g2.generation_id().to_string()));

    // 空转拒绝：同代际重复提交
    let err = coord.transact(&g3, |_| Ok(())).expect_err("同代际拒绝");
    assert_eq!(err.code(), CODE_GENERATION_UNCHANGED);
}

/// 真实崩溃可重放：子进程在提交点前（Prepared / Applied 两档）SIGABRT
/// 定格；父进程重开裁决——一律回滚挂起事务、旧代际保持有效、暂存目录
/// 清掉；recover 幂等（二次恢复零动作）。
#[test]
fn commit_point_crash_replay_subprocess() {
    // 子进程入口：注入环境在则执行崩溃体（不返回）
    if let Ok(phase) = std::env::var("RIL088_CHILD") {
        let dir = PathBuf::from(std::env::var("RIL088_DIR").expect("子进程须携 RIL088_DIR"));
        crash_child(&phase, &dir);
        unreachable!("crash_child 必 abort");
    }

    let dir = temp_state_dir("crash");
    let mut coord = PublishCoordinator::open(&dir).expect("open");
    let g1 = mk_gen("v1");
    coord.transact(&g1, |_| Ok(())).expect("首次发布");
    let g2 = mk_gen("v2");

    for phase in ["prepared", "applied"] {
        // 真子进程：定格磁盘后 SIGABRT（退出码必非成功）
        let status = Command::new(std::env::current_exe().expect("测试可执行"))
            .arg("commit_point_crash_replay_subprocess")
            .env("RIL088_CHILD", phase)
            .env("RIL088_DIR", &dir)
            .status()
            .expect("子进程启动");
        assert!(!status.success(), "子进程模拟崩溃（{phase}）");

        // 重开裁决：挂起在场 → 回滚
        let mut coord = PublishCoordinator::open(&dir).expect("崩溃后重开");
        let pending = coord.journal().pending.as_ref().expect("挂起事务在场");
        assert_eq!(pending.generation_id, g2.generation_id(), "挂起指向候选");
        assert_eq!(
            coord.effective(),
            Some(g1.generation_id()),
            "提交点前旧代际有效"
        );
        assert!(
            dir.join("generations").join(g2.generation_id()).exists(),
            "崩溃现场暂存目录在场"
        );

        let notes = coord.recover().expect("恢复");
        assert_eq!(notes.len(), 1, "回滚说明: {notes:?}");
        assert_eq!(
            coord.effective(),
            Some(g1.generation_id()),
            "回滚后旧代际保持有效（{phase}）"
        );
        assert!(coord.journal().pending.is_none(), "挂起清账");
        assert!(
            !dir.join("generations").join(g2.generation_id()).exists(),
            "暂存目录清掉"
        );

        // 幂等可重放：二次恢复零动作
        let notes = coord.recover().expect("二次恢复");
        assert!(notes.is_empty(), "recover 幂等: {notes:?}");
        // 先清掉本次崩溃候选目录，给下一档干净现场
        coord.reclaim(0).expect("现场复位");
    }

    // 两档崩溃注入后现役仍为 g1（发布面未被崩溃污染）
    let reread = PublishCoordinator::open(&dir).expect("终态重开");
    assert_eq!(reread.effective(), Some(g1.generation_id()));
}

/// 磁盘错误与未补偿可见：journal 路径损坏（目录占位）→ 落盘失败
/// Err、重开即一致（半态不留存）、遗留暂存以孤儿可见（不静默吸收），
/// 修复后重放成功；提交点后 / 记账前的崩溃——成功回执（effective）
/// 保留、漏账的旧代际以孤儿可见、reclaim 收敛且不回滚回执；排空先
/// 于回收（retained 驱动 drain，drain 完才 reclaim）。
#[test]
fn disk_faults_reopen_consistent_and_uncompensated_visible() {
    // —— journal 落盘失败：半态不留存、遗留可见、修复重放 ——
    let dir = temp_state_dir("disk-fault");
    let mut coord = PublishCoordinator::open(&dir).expect("open");
    let g1 = mk_gen("v1");
    coord.transact(&g1, |_| Ok(())).expect("首次发布");
    let g2 = mk_gen("v2");

    // journal 落盘失败：临时写路径（*.json.tmp）被目录占位 → 落盘段失败；
    // journal 正本无损（旧态完整保留）
    let tmp_path = dir.join("publish-journal.json.tmp");
    fs::create_dir_all(&tmp_path).expect("tmp 目录占位");
    let err = coord.transact(&g2, |_| Ok(())).expect_err("落盘失败须上抛");
    let PublishError::JournalCorrupt { detail } = &err else {
        panic!("落盘失败应为 JournalCorrupt: {err:?}");
    };
    assert!(detail.contains("落盘失败"), "失败点可解释: {detail}");
    assert_eq!(err.code(), CODE_JOURNAL_CORRUPT, "磁盘错误走损坏码");
    // 暂存目录已落（prepare 先于落盘）——重开对账可见
    assert!(
        dir.join("generations").join(g2.generation_id()).exists(),
        "prepare 半途遗留目录在场"
    );
    // 修复临时写路径后重开：journal 正本无损——半态不留存
    fs::remove_dir(&tmp_path).expect("修复 tmp 路径");
    let mut reread = PublishCoordinator::open(&dir).expect("重开");
    assert_eq!(reread.effective(), Some(g1.generation_id()), "半态不留存");
    assert!(reread.journal().pending.is_none(), "无挂起残留");
    let report = reread.reconcile();
    assert_eq!(
        report.orphans,
        vec![g2.generation_id().to_string()],
        "遗留暂存以孤儿可见（不被静默吸收）"
    );

    // 收敛孤儿 + 补偿重放
    reread.reclaim(0).expect("收敛孤儿");
    let outcome = reread.transact(&g2, |_| Ok(())).expect("修复后重放");
    assert_eq!(outcome.published, g2.generation_id());
    assert_eq!(reread.effective(), Some(g2.generation_id()));

    // —— 提交点后 / 记账前崩溃：回执保留、漏账孤儿可见、reclaim 收敛 ——
    let dir2 = temp_state_dir("retained-gap");
    let mut coord2 = PublishCoordinator::open(&dir2).expect("open");
    coord2.transact(&g1, |_| Ok(())).expect("发布 g1");
    // 手工定格：g2 已提交（effective 翻新）但 g1 退役记账未落（崩溃窗口）
    let staged2 = dir2.join("generations").join(g2.generation_id());
    fs::create_dir_all(&staged2).expect("候选暂存目录");
    fs::write(staged2.join("generation.json"), "candidate").expect("暂存内容");
    write_journal_raw(
        &dir2,
        &PublishJournal {
            effective: Some(EffectiveEntry {
                generation_id: g2.generation_id().to_string(),
                published_at_epoch: 0,
            }),
            pending: None,
            retained: vec![],
        },
    );
    let mut coord2 = PublishCoordinator::open(&dir2).expect("崩溃后重开");
    assert_eq!(
        coord2.effective(),
        Some(g2.generation_id()),
        "成功回执保留（提交点后不回滚）"
    );
    let report = coord2.reconcile();
    assert_eq!(report.retained, Vec::<String>::new(), "记账确实漏了");
    assert_eq!(
        report.orphans,
        vec![g1.generation_id().to_string()],
        "漏账旧代际以孤儿可见——不用成功回执掩盖"
    );
    let removed = coord2.reclaim(2).expect("收敛");
    assert!(
        removed.contains(&g1.generation_id().to_string()),
        "漏账孤儿收敛: {removed:?}"
    );
    assert_eq!(
        PublishCoordinator::open(&dir2)
            .expect("收敛后重开")
            .effective(),
        Some(g2.generation_id()),
        "收敛不回滚回执"
    );

    // —— 排空先于回收（RIL-023 消费侧对账）：retained 驱动 drain ——
    let dir3 = temp_state_dir("drain-before-reclaim");
    let mut coord3 = PublishCoordinator::open(&dir3).expect("open");
    coord3.transact(&g1, |_| Ok(())).expect("发布 g1");
    coord3.transact(&g2, |_| Ok(())).expect("发布 g2");
    let retired: Vec<String> = coord3
        .journal()
        .retained
        .iter()
        .map(|e| e.generation_id.clone())
        .collect();
    assert_eq!(
        retired,
        vec![g1.generation_id().to_string()],
        "retained 面在场"
    );
    // 旧代际上的会话：先排空（安全撤销——drain 后关闭留痕）
    let key = LeaseKey::new(
        &retired[0],
        "n1",
        Some(EndpointRef::new("203.0.113.10", 443)),
        "tenant-1",
        &["tls"],
    )
    .expect("合法租借键");
    let guard = LeaseGuard::begin(
        key,
        PoolResourceKind::Exclusive {
            target: EndpointRef::new("203.0.113.10", 443),
            reclaimable: true,
        },
    );
    guard
        .drain("generation retired")
        .expect("排空")
        .close()
        .expect("关闭留痕");
    // drain 完成 → 回收才动手：旧代际目录清除、现役不动
    coord3.reclaim(0).expect("回收");
    assert!(
        !dir3.join("generations").join(g1.generation_id()).exists(),
        "排空完毕后旧代际目录回收"
    );
    assert_eq!(
        PublishCoordinator::open(&dir3)
            .expect("回收后重开")
            .effective(),
        Some(g2.generation_id()),
        "回收不伤现役"
    );
}

/// 多客户端并发：单写者连续发布 + 多读者并发重开——读者永不见撕裂
/// journal（原子 rename 提交点：读到的一定是某次完整提交），effective
/// 恒属已知代际集（或初始 None）；终态 = 最后一次提交、retained 全账。
#[test]
fn concurrent_readers_never_observe_torn_journal() {
    let dir = temp_state_dir("concurrent");
    let tags: Vec<String> = (0..16).map(|i| format!("w{i}")).collect();
    let ids: Vec<String> = tags
        .iter()
        .map(|t| mk_gen(t).generation_id().to_string())
        .collect();
    let known: Arc<Vec<String>> = Arc::new(ids.clone());
    let done = Arc::new(AtomicBool::new(false));
    let opens = Arc::new(AtomicUsize::new(0));

    let mut readers = Vec::new();
    for _ in 0..3 {
        let dir = dir.clone();
        let known = known.clone();
        let done = done.clone();
        let opens = opens.clone();
        readers.push(std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let coord = PublishCoordinator::open(&dir).expect("并发重开必须成功");
                let seen = coord.effective().map(str::to_string).unwrap_or_default();
                assert!(
                    seen.is_empty() || known.iter().any(|k| k == &seen),
                    "读者只见已提交代际，不见撕裂态: {seen}"
                );
                // 镜像账面自洽：挂起（若有）必是真实候选且≠现役——
                // 原子 rename 保证读到的是某次完整提交，而非撕裂态
                if let Some(pending) = &coord.journal().pending {
                    assert!(
                        known.iter().any(|k| k == &pending.generation_id),
                        "挂起候选属已知代际集"
                    );
                    assert_ne!(
                        pending.generation_id, seen,
                        "挂起候选与现役不同（空转被拒）"
                    );
                }
                opens.fetch_add(1, Ordering::Relaxed);
                std::thread::yield_now();
            }
        }));
    }

    // 单写者：连续 16 次提交（每次数次原子落盘——大量读者观察窗口）
    let writer = {
        let dir = dir.clone();
        let tags = tags.clone();
        std::thread::spawn(move || {
            let mut coord = PublishCoordinator::open(&dir).expect("写者 open");
            for tag in &tags {
                let g = mk_gen(tag);
                coord.transact(&g, |_| Ok(())).expect("并发写提交");
            }
        })
    };
    writer.join().expect("写者收束");
    done.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().expect("读者收束");
    }
    assert!(
        opens.load(Ordering::Relaxed) > 100,
        "并发窗口真实发生（{} 次重开）",
        opens.load(Ordering::Relaxed)
    );

    // 终态对账：最后一次提交在场、retained 全账（15 条旧代际）
    let final_coord = PublishCoordinator::open(&dir).expect("终态重开");
    assert_eq!(
        final_coord.effective(),
        Some(ids.last().expect("非空").as_str()),
        "终态 = 最后一次提交"
    );
    assert_eq!(final_coord.journal().retained.len(), 15, "retained 全账");
    assert!(final_coord.journal().pending.is_none());
    let report = final_coord.reconcile();
    assert!(report.orphans.is_empty(), "无孤儿: {:?}", report.orphans);
}
