//! 来源快照原子替换（RIL-008）：以「来源版本」整体替换旧快照，取代
//! append-only 合并。一个来源的刷新只有在新内容**完整解析成功**时才
//! 发布新快照；解析失败旧快照原样保留；同内容 + 同解析器不重复发布
//! （不无意义发布——解析器版本变化仍可产生新快照）。更新/删除/同名/
//! 重复刷新语义经 RIL-002 `SourceSnapshot::diff` 显式给出。
//!
//! 边界：本层零网络（下载/缓存/退避归 RIL-010），parse 由调用方注入
//! （Clash/DSL/v2ray 各自的换算链）；内容摘要复用 SHA-256
//! （`SourceSnapshot::hash_content`），与既有 `Subscription::content_hash`
//! 同源；代际发布（GenerationStore 接线）归 RIL-019。

use std::collections::BTreeMap;

use rillane_config::{SnapshotDiff, SourceId, SourceObject, SourceSnapshot};

/// 刷新结果（RIL-008）：是否发布、发布差异全显式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// 发布了新快照（携带与旧版的 diff；首刷 diff 为空清单+全量 added 计
    /// 入 added——首刷视作从零发布）
    Published {
        /// 与旧快照的差异
        diff: SnapshotDiff,
    },
    /// 内容与解析器版本都没变：不发布（重复刷新无新意）
    Unchanged,
}

/// 刷新错误：新内容解析失败——旧快照保持不变（失败保留旧快照）。
#[derive(Debug, thiserror::Error)]
#[error("来源 {} 刷新失败（旧快照保留）: {reason}", source_id.as_str())]
pub struct RefreshError {
    /// 来源
    pub source_id: SourceId,
    /// 失败原因（转换链错误文案）
    pub reason: String,
}

/// 来源快照存储（RIL-008）：按 [`SourceId`] 原子替换。
#[derive(Debug, Default)]
pub struct SourceSnapshotStore {
    snapshots: BTreeMap<SourceId, SourceSnapshot>,
    /// 解析器版本（来源版本参与方：解析器升级后同内容也重新发布）
    parser_version: u32,
}

impl SourceSnapshotStore {
    /// 构造存储；parser_version 随解析链版本演进手动递增
    pub fn new(parser_version: u32) -> Self {
        Self {
            snapshots: BTreeMap::new(),
            parser_version,
        }
    }

    /// 当前解析器版本
    pub fn parser_version(&self) -> u32 {
        self.parser_version
    }

    /// 查询某来源当前快照（失败/未刷新时保留的上一个成功版本）
    pub fn snapshot(&self, source: &SourceId) -> Option<&SourceSnapshot> {
        self.snapshots.get(source)
    }

    /// 快照数量
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// 整源移除（删除语义：返回被移除的快照供下游清理由此产生的候选）
    pub fn remove(&mut self, source: &SourceId) -> Option<SourceSnapshot> {
        self.snapshots.remove(source)
    }

    /// 原子刷新一个来源（RIL-008 验收主路径）：`parse` 把原始内容换算为
    /// 来源对象（由调用方注入格式转换链）。失败（parse 返回 Err）时旧
    /// 快照原样保留；成功才整体替换为新快照。同 `content_hash` + 同
    /// `parser_version` 的重复刷新返回 [`RefreshOutcome::Unchanged`]，
    /// 不产生新快照对象。
    pub fn refresh_with<E>(
        &mut self,
        source: SourceId,
        content: &str,
        parse: impl FnOnce(&str) -> Result<Vec<SourceObject>, E>,
    ) -> Result<RefreshOutcome, RefreshError>
    where
        E: std::fmt::Display,
    {
        let content_hash = SourceSnapshot::hash_content(content.as_bytes());

        // 同内容 + 同解析器：不无意义发布（fetch/etag 之外的第二道闸）
        if let Some(old) = self.snapshots.get(&source) {
            if old.content_hash == content_hash && old.parser_version == self.parser_version {
                return Ok(RefreshOutcome::Unchanged);
            }
        }

        // 解析失败：旧快照不动（验收「失败保留旧快照」）
        let objects = parse(content).map_err(|err| RefreshError {
            source_id: source.clone(),
            reason: err.to_string(),
        })?;

        let next = SourceSnapshot {
            source: source.clone(),
            content_hash,
            parser_version: self.parser_version,
            fetched_at_unix_ms: now_unix_ms(),
            objects,
        };

        // diff 与替换一步完成：旧代可被存活引用（快照不可变，替换只换
        // 存储位指向），更新/删除/改名/同名语义全在 diff 里
        let diff = match self.snapshots.get(&source) {
            Some(old) => match old.diff(&next) {
                Ok(diff) => diff,
                // 同源 diff 唯一错误是跨来源不匹配——next.source 就是 source，
                // 实际不可达；保守按刷新失败处理且不发布
                Err(err) => {
                    return Err(RefreshError {
                        source_id: source.clone(),
                        reason: err.to_string(),
                    })
                }
            },
            None => SnapshotDiff {
                added: next.objects.iter().map(|o| o.id.clone()).collect(),
                removed: Vec::new(),
                renamed: Vec::new(),
                unchanged: 0,
            },
        };

        self.snapshots.insert(source, next);
        Ok(RefreshOutcome::Published { diff })
    }

    /// 升级解析器版本：之后同内容刷新也会重新发布（解析器变化可产生
    /// 新代际，架构 §4.1）
    pub fn set_parser_version(&mut self, parser_version: u32) {
        self.parser_version = parser_version;
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rillane_config::{
        derive_local_id, ObjectId, ObjectKind, SourceLocation, CODE_SOURCE_MISMATCH,
    };

    fn src(name: &str) -> SourceId {
        SourceId::new(name).unwrap()
    }

    /// 测试对象：内容身份派生 local_id——「香港 01」类同名对象靠身份区分
    fn node(source: &SourceId, name: &str, server: &str, pointer: &str) -> SourceObject {
        SourceObject {
            id: ObjectId::new(source.clone(), derive_local_id(&["vmess", server, "443"])),
            kind: ObjectKind::Node,
            display_name: name.to_string(),
            location: SourceLocation::new(source.clone(), pointer),
        }
    }

    /// 解析桩：内容形如 "server1,server2" → 每台服务器一个节点对象
    fn parse_stub(content: &str) -> Result<Vec<SourceObject>, String> {
        if content.trim() == "BAD" {
            return Err("模拟解析失败".to_string());
        }
        let source = src("airport");
        Ok(content
            .split(',')
            .filter(|s| !s.is_empty())
            .enumerate()
            .map(|(i, server)| {
                node(
                    &source,
                    &format!("节点-{i}"),
                    server,
                    &format!("proxies/{i}"),
                )
            })
            .collect())
    }

    #[test]
    fn first_refresh_publishes_full_set() {
        let mut store = SourceSnapshotStore::new(1);
        let outcome = store
            .refresh_with(src("airport"), "1.1.1.1,2.2.2.2", parse_stub)
            .unwrap();
        let RefreshOutcome::Published { diff } = outcome else {
            panic!("首刷必须发布");
        };
        assert_eq!(diff.added.len(), 2);
        assert!(diff.removed.is_empty());
        assert_eq!(store.snapshot(&src("airport")).unwrap().objects.len(), 2);
    }

    #[test]
    fn repeated_refresh_same_content_is_unchanged() {
        // 验收：重复刷新——同内容+同解析器不重发
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        let before = store.snapshot(&src("airport")).unwrap().clone();
        let outcome = store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        assert_eq!(outcome, RefreshOutcome::Unchanged);
        let after = store.snapshot(&src("airport")).unwrap();
        assert_eq!(
            before.content_hash, after.content_hash,
            "重复刷新不得产生新快照版本"
        );
    }

    #[test]
    fn update_delete_and_same_name_are_explicit() {
        // 验收：更新、删除、同名
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(src("airport"), "1.1.1.1,2.2.2.2,3.3.3.3", parse_stub)
            .unwrap();

        // 更新：2.2.2.2 换 9.9.9.9（新增），3.3.3.3 删除（removed），
        // 1.1.1.1 保留（unchanged）；同名对象「节点-0」身份不变不是改名
        let outcome = store
            .refresh_with(src("airport"), "1.1.1.1,9.9.9.9", parse_stub)
            .unwrap();
        let RefreshOutcome::Published { diff } = outcome else {
            panic!("内容变化必须发布");
        };
        assert_eq!(diff.unchanged, 1, "1.1.1.1 保留");
        assert_eq!(diff.added.len(), 1, "9.9.9.9 新增");
        assert_eq!(diff.removed.len(), 2, "2.2.2.2 与 3.3.3.3 显式删除");
        assert!(diff.renamed.is_empty(), "同名新身份≠改名");
        assert_eq!(store.snapshot(&src("airport")).unwrap().objects.len(), 2);
    }

    #[test]
    fn failed_refresh_keeps_previous_snapshot() {
        // 验收：失败保留旧快照
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        let before = store.snapshot(&src("airport")).unwrap().clone();

        let err = store
            .refresh_with(src("airport"), "BAD", parse_stub)
            .unwrap_err();
        assert_eq!(err.source_id, src("airport"));
        assert!(err.reason.contains("解析失败"));

        let after = store.snapshot(&src("airport")).unwrap();
        assert_eq!(
            after.content_hash, before.content_hash,
            "失败刷新后旧快照原样保留"
        );
        assert_eq!(after.objects.len(), before.objects.len());
    }

    #[test]
    fn parser_version_change_republishes_same_content() {
        // 解析器升级：同内容重新发布（解析器版本入来源版本）
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        store.set_parser_version(2);
        let outcome = store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Published { .. }),
            "解析器变化须重新发布"
        );
        assert_eq!(store.snapshot(&src("airport")).unwrap().parser_version, 2);
    }

    #[test]
    fn remove_source_returns_last_snapshot() {
        // 验收：删除——整源移除，返回最后成功快照；重复移除为空
        let mut store = SourceSnapshotStore::new(1);
        store
            .refresh_with(src("airport"), "1.1.1.1", parse_stub)
            .unwrap();
        let removed = store.remove(&src("airport")).expect("移除返回旧快照");
        assert_eq!(removed.objects.len(), 1);
        assert!(store.snapshot(&src("airport")).is_none());
        assert!(store.remove(&src("airport")).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn cross_source_snapshots_coexist() {
        // 多来源互不干扰；同名对象跨来源共存（RIL-002 语义在存储层保持）
        let mut store = SourceSnapshotStore::new(1);
        store.refresh_with(src("a"), "1.1.1.1", parse_stub).unwrap();
        store.refresh_with(src("b"), "1.1.1.1", parse_stub).unwrap();
        assert_eq!(store.len(), 2);
        let a = store.snapshot(&src("a")).unwrap();
        let b = store.snapshot(&src("b")).unwrap();
        assert_ne!(a.source, b.source);
        // 稳定码守恒：跨源比较的错在 diff 层（这里直接构造断言一次）
        let err = a.diff(b).unwrap_err();
        assert_eq!(err.code(), CODE_SOURCE_MISMATCH);
    }
}
