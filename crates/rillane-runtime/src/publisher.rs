//! 配置发布协调器（RIL-019）：生成代际的事务化发布——
//! prepare → apply → publish → drain → reclaim 五段与持久化顺序。
//!
//! **持久化顺序（验收：磁盘与有效状态可解释且可对账）**：journal 文件
//! 是唯一权威——每段先落 journal（写临时文件 + rename 原子替换），再动
//! 内存镜像与磁盘目录。publish 是**提交点**：journal 里 effective 翻到
//! 新代际即生效；提交点之前的任何中断（prepare/applied 挂起）恢复时
//! 一律回滚——旧代际保持有效，OS 面由启动装配按 effective 代际重新
//! 导出，不存在「半应用」稳态。
//!
//! **崩溃可恢复**：`recover()` 启动时读 journal——`pending: Prepared`
//! （候选已暂存未应用）丢弃暂存目录；`pending: Applied`（应用成功但
//! 提交未落）同样回滚（应用幂等，未提交即不作数）。
//!
//! **可对账**：`reconcile()` 报告 effective / 暂存 / 保留 / 孤儿（磁盘
//! 有目录而 journal 无记录）四类，`reclaim()` 收敛——孤儿与超保留界的
//! 保留代际一并清除。
//!
//! 接线边界：runtime 配置面的接线（订阅刷新 → 代际 → transact）与
//! OS 面的 drain 会话排空归 RIL-022/023 消费侧；本模块只契约化发布
//! 事务与磁盘状态。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use rillane_config::RuntimeGeneration;

/// 稳定原因码：journal 损坏（不可解析 / 身份不一致）——不猜语义。
pub const CODE_JOURNAL_CORRUPT: &str = "publish.journal.corrupt";
/// 稳定原因码：事务中代际与现役代际相同（无变化，拒绝空转提交）。
pub const CODE_GENERATION_UNCHANGED: &str = "publish.generation.unchanged";

/// 发布协调器错误（文案可演进，`code()` 恒定）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// journal 文件损坏
    #[error("{CODE_JOURNAL_CORRUPT}: 发布 journal 不可解析: {detail}")]
    JournalCorrupt {
        /// 人读细节
        detail: String,
    },
    /// 候选代际与现役代际相同
    #[error("{CODE_GENERATION_UNCHANGED}: 候选代际 {generation_id} 与现役代际相同，拒绝空转发布")]
    GenerationUnchanged {
        /// 候选代际身份
        generation_id: String,
    },
    /// apply 阶段失败（OS 面/运行时面应用失败——旧代际保留）
    #[error("发布事务 apply 失败（旧代际保留）: {0}")]
    ApplyFailed(String),
}

impl PublishError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            PublishError::JournalCorrupt { .. } => CODE_JOURNAL_CORRUPT,
            PublishError::GenerationUnchanged { .. } => CODE_GENERATION_UNCHANGED,
            PublishError::ApplyFailed(_) => "publish.apply.failed",
        }
    }
}

/// 事务阶段（journal 持久化面）：Prepared = 候选已暂存；Applied =
/// 应用回调成功、提交未落。恢复口径：两者都回滚（publish 才是提交点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishPhase {
    Prepared,
    Applied,
}

/// 挂起事务（journal `pending` 面）：Some = 存在未完成事务，恢复时裁决。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTx {
    /// 候选代际身份
    pub generation_id: String,
    /// 已到达的阶段
    pub phase: PublishPhase,
    /// 事务开始时刻（epoch 秒；诊断用，不参与裁决）
    pub started_at_epoch: u64,
}

/// 现役代际条目（journal `effective` 面）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveEntry {
    /// 现役代际身份
    pub generation_id: String,
    /// 提交时刻（epoch 秒）
    pub published_at_epoch: u64,
}

/// 已退役保留代际（drain 面产物，reclaim 的收敛对象）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedEntry {
    /// 退役代际身份
    pub generation_id: String,
    /// 退役时刻（epoch 秒）
    pub retired_at_epoch: u64,
}

/// 发布 journal（磁盘权威状态）：`<state_dir>/publish-journal.json`。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PublishJournal {
    /// 现役代际；None = 从未发布过
    #[serde(default)]
    pub effective: Option<EffectiveEntry>,
    /// 未完成事务；None = 无挂起
    #[serde(default)]
    pub pending: Option<PendingTx>,
    /// 已退役保留代际（新→旧序，reclaim 从尾部收敛）
    #[serde(default)]
    pub retained: Vec<RetainedEntry>,
}

impl PublishJournal {
    fn load(path: &Path) -> Result<Self, PublishError> {
        match fs::read_to_string(path) {
            Ok(text) => {
                if text.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_json::from_str(&text).map_err(|e| PublishError::JournalCorrupt {
                    detail: e.to_string(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(PublishError::JournalCorrupt {
                detail: e.to_string(),
            }),
        }
    }

    /// 原子落盘：写临时文件 + rename（持久化顺序——journal 是提交权威，
    /// 半写的临时文件永不生效）。
    fn store(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_string_pretty(self).expect("journal 可序列化"),
        )?;
        fs::rename(&tmp, path)
    }
}

/// 对账报告（`reconcile()` 产物）：磁盘与有效状态的四类解释。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReport {
    /// 现役代际（journal 权威）；None = 从未发布
    pub effective: Option<String>,
    /// 候选暂存目录（有 pending 或遗留）
    pub staged: Vec<String>,
    /// 保留代际（journal retained 面）
    pub retained: Vec<String>,
    /// 孤儿：磁盘有目录而 journal 无任何记录（reclaim 清除对象）
    pub orphans: Vec<String>,
}

fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// 配置发布协调器：管理 `<state_dir>` 下的 journal 与代际暂存目录。
pub struct PublishCoordinator {
    state_dir: PathBuf,
    journal_path: PathBuf,
    journal: PublishJournal,
}

impl PublishCoordinator {
    /// 打开（或初始化）协调器。journal 不可解析即拒绝——磁盘损坏不猜
    /// 语义，要求人工对账（`CODE_JOURNAL_CORRUPT`）。
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, PublishError> {
        let state_dir = state_dir.into();
        let journal_path = state_dir.join("publish-journal.json");
        let journal = PublishJournal::load(&journal_path)?;
        Ok(Self {
            state_dir,
            journal_path,
            journal,
        })
    }

    /// 代际暂存目录
    fn gen_dir(&self, generation_id: &str) -> PathBuf {
        self.state_dir.join("generations").join(generation_id)
    }

    /// 暂存候选代际（prepare 段的磁盘面）：序列化进
    /// `generations/<gid>/generation.json`。已存在同身份目录视为幂等
    /// 重入（同内容必同身份）。
    fn stage(&self, generation: &RuntimeGeneration) -> std::io::Result<()> {
        let dir = self.gen_dir(generation.generation_id());
        fs::create_dir_all(&dir)?;
        let text = serde_json::to_string_pretty(generation).expect("代际可序列化");
        fs::write(dir.join("generation.json"), text)
    }

    fn persist(&mut self) -> Result<(), PublishError> {
        self.journal
            .store(&self.journal_path)
            .map_err(|e| PublishError::JournalCorrupt {
                detail: format!("journal 落盘失败: {e}"),
            })
    }

    /// 当前有效代际身份
    pub fn effective(&self) -> Option<&str> {
        self.journal
            .effective
            .as_ref()
            .map(|e| e.generation_id.as_str())
    }

    /// journal 只读镜像（诊断/控制面取数）
    pub fn journal(&self) -> &PublishJournal {
        &self.journal
    }

    /// 恢复：裁决挂起事务（启动时调用一次）。
    ///
    /// - `pending: Prepared` → 丢弃暂存目录、清 pending（旧代际保持有效）
    /// - `pending: Applied`  → 清 pending、同弃暂存（应用幂等、未提交
    ///   即不作数；OS 面由启动装配按 effective 重新导出）
    ///
    /// 返回恢复动作说明（可观察性；空 = 无挂起事务）。
    pub fn recover(&mut self) -> Result<Vec<String>, PublishError> {
        let Some(pending) = self.journal.pending.take() else {
            return Ok(Vec::new());
        };
        let dir = self.gen_dir(&pending.generation_id);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| PublishError::JournalCorrupt {
                detail: format!("暂存目录清理失败: {e}"),
            })?;
        }
        let note = format!(
            "回滚挂起事务 {}（{:?}）：未过发布提交点，旧代际保持有效",
            pending.generation_id, pending.phase
        );
        self.persist()?;
        Ok(vec![note])
    }

    /// 完整发布事务：prepare → apply → publish（提交点）→ drain 记账。
    ///
    /// 持久化顺序：
    /// 1. prepare：暂存目录 + journal `pending{Prepared}` 先落盘
    /// 2. apply：调用方回调把候选应用到运行时/OS 面；失败 → 清 pending
    ///    （Err 返回，**旧代际保留**——验收「OS 应用失败保留旧代际」）
    /// 3. publish：journal `effective` 翻新 + 清 pending 一次原子写——
    ///    提交点；之后旧代际进 `retained`（drain 记账面，会话排空由
    ///    消费侧按 retained 旧代际执行）
    ///
    /// `apply` 回调要求幂等：恢复路径可能让启动装配重新应用 effective。
    pub fn transact<F>(
        &mut self,
        candidate: &RuntimeGeneration,
        apply: F,
    ) -> Result<PublishTxnOutcome, PublishError>
    where
        F: FnOnce(&RuntimeGeneration) -> Result<(), String>,
    {
        let candidate_id = candidate.generation_id().to_string();
        if self.effective() == Some(candidate_id.as_str()) {
            return Err(PublishError::GenerationUnchanged {
                generation_id: candidate_id,
            });
        }

        // —— prepare：先磁盘后 journal（半途崩溃恢复见 recover）——
        self.stage(candidate)
            .map_err(|e| PublishError::JournalCorrupt {
                detail: format!("候选代际暂存失败: {e}"),
            })?;
        self.journal.pending = Some(PendingTx {
            generation_id: candidate_id.clone(),
            phase: PublishPhase::Prepared,
            started_at_epoch: epoch_now(),
        });
        self.persist()?;

        // —— apply：失败即回滚 pending，旧代际保留 ——
        if let Err(reason) = apply(candidate) {
            self.journal.pending = None;
            self.persist()?;
            let _ = fs::remove_dir_all(self.gen_dir(&candidate_id));
            return Err(PublishError::ApplyFailed(reason));
        }
        self.journal.pending = Some(PendingTx {
            phase: PublishPhase::Applied,
            ..self.journal.pending.take().expect("pending 在场")
        });
        self.persist()?;

        // —— publish：提交点（一次原子写翻 effective + 清 pending）——
        let previous = self.journal.effective.take();
        let previous_id = previous.as_ref().map(|e| e.generation_id.clone());
        self.journal.effective = Some(EffectiveEntry {
            generation_id: candidate_id.clone(),
            published_at_epoch: epoch_now(),
        });
        self.journal.pending = None;
        self.persist()?;

        // —— drain 记账：旧代际进 retained（消费侧按此排空会话）——
        if let Some(old) = previous {
            self.journal.retained.insert(
                0,
                RetainedEntry {
                    generation_id: old.generation_id,
                    retired_at_epoch: epoch_now(),
                },
            );
            self.persist()?;
        }

        Ok(PublishTxnOutcome {
            published: candidate_id,
            previous: previous_id,
        })
    }

    /// 对账：磁盘与有效状态的四类解释（验收「可解释且可对账」）。
    pub fn reconcile(&self) -> ReconcileReport {
        let mut report = ReconcileReport {
            effective: self.effective().map(str::to_string),
            ..Default::default()
        };
        let gens_dir = self.state_dir.join("generations");
        let entries = match fs::read_dir(&gens_dir) {
            Ok(entries) => entries,
            Err(_) => return report,
        };
        let mut known: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Some(pending) = &self.journal.pending {
            report.staged.push(pending.generation_id.clone());
            known.insert(pending.generation_id.clone());
        }
        for entry in &self.journal.retained {
            report.retained.push(entry.generation_id.clone());
            known.insert(entry.generation_id.clone());
        }
        if let Some(effective) = &self.journal.effective {
            known.insert(effective.generation_id.clone());
        }
        let mut disk_ids: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        disk_ids.sort();
        for id in disk_ids {
            if !known.contains(&id) {
                report.orphans.push(id);
            }
        }
        report
    }

    /// 收敛（reclaim 段）：清除孤儿目录与超保留界的退役代际（保留最新
    /// `keep_retained` 个）。journal 持久化先于目录删除——先记账后动手，
    /// 中断只多留目录（下次对账可见），不留无账目录。
    pub fn reclaim(&mut self, keep_retained: usize) -> Result<Vec<String>, PublishError> {
        let mut removed = Vec::new();

        // 孤儿：journal 无记录的磁盘目录
        let report = self.reconcile();
        for orphan in &report.orphans {
            let dir = self.state_dir.join("generations").join(orphan);
            if fs::remove_dir_all(&dir).is_ok() {
                removed.push(orphan.clone());
            }
        }

        // 退役代际超界：journal 先删账，再删目录
        while self.journal.retained.len() > keep_retained {
            let entry = self.journal.retained.pop().expect("长度已核对");
            removed.push(entry.generation_id.clone());
        }
        self.persist()?;
        for id in &removed {
            let _ = fs::remove_dir_all(self.state_dir.join("generations").join(id));
        }
        Ok(removed)
    }
}

/// 一次发布事务的结果（可观察面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishTxnOutcome {
    /// 新现役代际
    pub published: String,
    /// 被顶替的旧代际（None = 首次发布）
    pub previous: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::{GenerationObject, ObjectId, ObjectKind, SourceId};

    fn temp_state_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rillane-publish-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 构造含一个节点对象的代际；tag 进对象内容摘要——不同 tag 必不同代际
    fn gen(tag: &str) -> RuntimeGeneration {
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

    #[test]
    fn transact_publishes_and_persists_commit_point() {
        let dir = temp_state_dir("txn");
        let mut coord = PublishCoordinator::open(&dir).expect("open");
        assert_eq!(coord.effective(), None, "初始无现役");

        let g1 = gen("v1");
        let outcome = coord.transact(&g1, |_| Ok(())).expect("首次发布成功");
        assert_eq!(outcome.published, g1.generation_id());
        assert_eq!(outcome.previous, None);
        assert_eq!(coord.effective(), Some(g1.generation_id()));

        // journal 磁盘权威：重新 open 读到同一 effective（持久化在内存之前）
        let reread = PublishCoordinator::open(&dir).expect("re-open");
        assert_eq!(reread.effective(), Some(g1.generation_id()));
        assert!(reread.journal().pending.is_none(), "无挂起");
        assert!(
            dir.join("generations")
                .join(g1.generation_id())
                .join("generation.json")
                .exists(),
            "代际内容已暂存落盘"
        );

        // 二次发布：旧代际进 retained（drain 记账面）
        let g2 = gen("v2");
        let outcome = coord.transact(&g2, |_| Ok(())).expect("二次发布");
        assert_eq!(outcome.previous, Some(g1.generation_id().to_string()));
        assert_eq!(coord.journal().retained.len(), 1);
        assert_eq!(
            coord.journal().retained[0].generation_id,
            g1.generation_id(),
            "旧代际记账保留"
        );
    }

    #[test]
    fn apply_failure_keeps_old_generation() {
        let dir = temp_state_dir("apply-fail");
        let mut coord = PublishCoordinator::open(&dir).expect("open");
        let g1 = gen("v1");
        coord.transact(&g1, |_| Ok(())).expect("首次发布");
        let old_effective = g1.generation_id().to_string();

        // 候选 apply 失败 → Err、旧代际保留、无挂起、暂存目录清掉
        let g2 = gen("v2");
        let err = coord
            .transact(&g2, |_| Err("OS 应用失败: 路由规则写入被拒".to_string()))
            .expect_err("apply 失败须上抛");
        assert!(matches!(err, PublishError::ApplyFailed(_)));
        assert_eq!(
            coord.effective(),
            Some(old_effective.as_str()),
            "旧代际保留"
        );
        assert!(coord.journal().pending.is_none(), "无挂起事务");
        let reread = PublishCoordinator::open(&dir).expect("re-open");
        assert_eq!(reread.effective(), Some(old_effective.as_str()));
        assert!(reread.journal().pending.is_none());
        assert!(
            !dir.join("generations").join(g2.generation_id()).exists(),
            "失败候选的暂存目录已清"
        );

        // 同代际重发拒绝空转
        let err = coord.transact(&g1, |_| Ok(())).expect_err("同代际拒绝");
        assert_eq!(err.code(), CODE_GENERATION_UNCHANGED);
    }

    #[test]
    fn recovery_rolls_back_prepared_and_applied() {
        // 崩溃在 prepare 之后：journal 有 pending Prepared + 暂存目录
        let dir = temp_state_dir("recover-prepared");
        let mut coord = PublishCoordinator::open(&dir).expect("open");
        let g1 = gen("v1");
        coord.transact(&g1, |_| Ok(())).expect("首次发布");
        let g2 = gen("v2");
        let staged = dir.join("generations").join(g2.generation_id());
        fs::create_dir_all(&staged).unwrap();
        fs::write(staged.join("generation.json"), "x").unwrap();
        coord.journal.pending = Some(PendingTx {
            generation_id: g2.generation_id().to_string(),
            phase: PublishPhase::Prepared,
            started_at_epoch: 0,
        });
        coord.persist().expect("persist");

        let notes = coord.recover().expect("recover");
        assert_eq!(notes.len(), 1, "回滚说明: {notes:?}");
        assert_eq!(
            coord.effective(),
            Some(g1.generation_id()),
            "旧代际保持有效"
        );
        assert!(coord.journal.pending.is_none());
        assert!(!staged.exists(), "暂存目录清掉");

        // 崩溃在 apply 之后、publish 之前：pending Applied 同样回滚
        let dir = temp_state_dir("recover-applied");
        let mut coord = PublishCoordinator::open(&dir).expect("open");
        coord.transact(&g1, |_| Ok(())).expect("首次发布");
        coord.journal.pending = Some(PendingTx {
            generation_id: g2.generation_id().to_string(),
            phase: PublishPhase::Applied,
            started_at_epoch: 0,
        });
        coord.persist().expect("persist");
        let notes = coord.recover().expect("recover");
        assert_eq!(notes.len(), 1);
        assert_eq!(coord.effective(), Some(g1.generation_id()), "未提交不作数");
        assert!(coord.journal.pending.is_none());
    }

    #[test]
    fn reconcile_reports_disk_vs_effective_and_reclaim_converges() {
        let dir = temp_state_dir("reconcile");
        let mut coord = PublishCoordinator::open(&dir).expect("open");

        // 连发三个代际（每个都顶替前者，retained 增长）
        let g1 = gen("v1");
        coord.transact(&g1, |_| Ok(())).expect("p1");
        let g2 = gen("v2");
        coord.transact(&g2, |_| Ok(())).expect("p2");
        let g3 = gen("v3");
        coord.transact(&g3, |_| Ok(())).expect("p3");

        // 手工造一个孤儿目录（磁盘有、journal 无）
        let orphan = dir.join("generations").join("orphan-gid");
        fs::create_dir_all(&orphan).unwrap();

        let report = coord.reconcile();
        assert_eq!(report.effective, Some(g3.generation_id().to_string()));
        assert!(report.staged.is_empty(), "无挂起: {:?}", report.staged);
        assert_eq!(
            report.retained,
            vec![
                g2.generation_id().to_string(),
                g1.generation_id().to_string()
            ],
            "retained 新→旧序"
        );
        assert_eq!(report.orphans, vec!["orphan-gid".to_string()]);

        // reclaim：孤儿清除 + retained 收敛到 1（最新退役）
        let removed = coord.reclaim(1).expect("reclaim");
        assert!(
            removed.iter().any(|i| i == "orphan-gid"),
            "孤儿清除: {removed:?}"
        );
        assert!(
            removed.iter().any(|id| id == g1.generation_id()),
            "最旧退役清除: {removed:?}"
        );
        assert!(!orphan.exists());
        let report = coord.reconcile();
        assert_eq!(report.orphans.len(), 0);
        assert_eq!(report.retained.len(), 1);
        assert_eq!(
            report.retained[0],
            g2.generation_id().to_string(),
            "保留最新退役"
        );

        // journal 磁盘权威对账：re-open 读到收敛后状态
        let reread = PublishCoordinator::open(&dir).expect("re-open");
        assert_eq!(reread.journal().retained.len(), 1);
        assert_eq!(reread.effective(), Some(g3.generation_id()));
    }

    #[test]
    fn corrupt_journal_is_rejected_not_guessed() {
        let dir = temp_state_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("publish-journal.json"), "{{{ not json").unwrap();
        let err = PublishCoordinator::open(&dir)
            .err()
            .expect("损坏 journal 拒绝");
        assert_eq!(err.code(), CODE_JOURNAL_CORRUPT);
    }
}
