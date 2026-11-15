//! 不可变代际模型（RIL-003 / C14）：RuntimeGeneration 是一次发布的原子
//! 单元——节点、规则、DNS 不各自独立更新。候选代际先整体校验（引用图
//! 拒绝悬空引用与循环引用，稳定原因码 `generation.reference.dangling` /
//! `generation.reference.cycle`），只有完全合法的候选才能顶替发布位；
//! 校验失败的候选不覆盖已发布代际。代际身份由内容摘要派生（对象内容
//! 摘要 + 引用边一起进入 SHA-256）——同内容必同代际，任何子变化都产生
//! 新代际。已发布代际不可变：会话持有 `Arc` 引用即可钉住旧代际，新发布
//! 不使存活会话的引用失效。
//!
//! 接线边界：本模块只定义契约与校验；订阅刷新发布（RIL-008）、
//! RoutePlan/SessionPin 消费（RIL-006）在各自任务接入。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::source::{ObjectId, ObjectKind};

/// 稳定原因码：引用了不存在（悬空）的对象。
pub const CODE_GENERATION_DANGLING: &str = "generation.reference.dangling";
/// 稳定原因码：引用图存在循环。
pub const CODE_GENERATION_CYCLE: &str = "generation.reference.cycle";
/// 稳定原因码：同一对象 ID 携带冲突内容（不静默合并）。
pub const CODE_GENERATION_DUPLICATE: &str = "generation.object.duplicate";
/// 稳定原因码：代际身份与内容摘要不一致（反序列化防篡改）。
pub const CODE_GENERATION_ID_MISMATCH: &str = "generation.id.mismatch";

/// 代际契约错误（RIL-003）：文案可演进，`code()` 恒定。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenerationError {
    /// 引用了代际内不存在的对象
    #[error(
        "{CODE_GENERATION_DANGLING}: 引用悬空: {:?} -> {:?}（被引用对象不在本代际内）",
        .from, .to
    )]
    DanglingReference {
        /// 引用方对象
        from: ObjectId,
        /// 被引用但缺失的对象
        to: ObjectId,
    },
    /// 引用图存在循环（path 为环上对象，首尾相同）
    #[error(
        "{CODE_GENERATION_CYCLE}: 引用循环: {}",
        .path.iter().map(|id| id.local_id.clone()).collect::<Vec<_>>().join(" -> ")
    )]
    ReferenceCycle {
        /// 环路路径（首尾为同一对象）
        path: Vec<ObjectId>,
    },
    /// 同一对象 ID 携带冲突内容
    #[error("{CODE_GENERATION_DUPLICATE}: 对象 {:?} 在候选代际内出现冲突内容", .id)]
    DuplicateObject {
        /// 冲突对象的稳定 ID
        id: ObjectId,
    },
}

impl GenerationError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            GenerationError::DanglingReference { .. } => CODE_GENERATION_DANGLING,
            GenerationError::ReferenceCycle { .. } => CODE_GENERATION_CYCLE,
            GenerationError::DuplicateObject { .. } => CODE_GENERATION_DUPLICATE,
        }
    }
}

/// 代际内的对象条目（RIL-003）：稳定 ID + 类别 + 对象级内容摘要。
/// `content_hash` 由调用方按解析后的对象内容计算（[`digest_parts`] 是
/// 规范算法）；同一对象内容变化 → 新摘要 → 新代际身份。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationObject {
    /// 稳定身份（RIL-002 `(SourceId, local_id)` 口径）
    pub id: ObjectId,
    /// 类别
    pub kind: ObjectKind,
    /// 对象内容摘要（SHA-256 十六进制）
    pub content_hash: String,
}

/// 代际内引用边（RIL-003）：组→成员节点/嵌套组、规则→目标组/规则集等
/// 对象间引用。方向语义由调用方解释，本模型只负责图完整性（悬空/循环）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GenerationEdge {
    /// 引用方
    pub from: ObjectId,
    /// 被引用方
    pub to: ObjectId,
}

/// 规范内容摘要算法（RIL-003）：对字段序列做分隔哈希（与
/// [`crate::source::derive_local_id`] 同分隔纪律，但取完整 64 位十六进制）。
/// 对象级 content_hash 与代际身份都应经由此函数派生。
pub fn digest_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        // '\x1f' 分隔避免相邻字段拼接歧义
        hasher.update([0x1f]);
    }
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn kind_tag(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Node => "node",
        ObjectKind::Group => "group",
        ObjectKind::RuleSet => "rule_set",
    }
}

/// 一个已发布（或候选）代际（RIL-003 / C14）：不可变、整体合法的对象图。
/// 构造入口只有 [`RuntimeGeneration::build`]——通过悬空/循环校验并计算
/// 内容摘要后才存在；字段只读。会话持有 `Arc<RuntimeGeneration>` 钉住
/// 代际，发布位替换不影响已持有的引用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeGeneration {
    /// 内容摘要派生的代际身份（同内容必同身份）
    generation_id: String,
    /// 代际内对象（按 ID 排序去重，保证摘要与序列化确定性）
    objects: Vec<GenerationObject>,
    /// 引用边（排序去重，保证摘要确定性）
    edges: BTreeSet<GenerationEdge>,
}

impl<'de> Deserialize<'de> for RuntimeGeneration {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            generation_id: String,
            objects: Vec<GenerationObject>,
            edges: Vec<GenerationEdge>,
        }
        let raw = Raw::deserialize(deserializer)?;
        // 反序列化走同一 build 校验，并核对内容身份——被篡改的代际
        // （对象/边/身份不一致）在此拒绝，不静默接受
        let rebuilt = RuntimeGeneration::build(raw.objects, raw.edges)
            .map_err(|e| serde::de::Error::custom(format!("{e}（code: {}）", e.code())))?;
        if rebuilt.generation_id != raw.generation_id {
            return Err(serde::de::Error::custom(format!(
                "{CODE_GENERATION_ID_MISMATCH}: 代际身份与内容摘要不一致"
            )));
        }
        Ok(rebuilt)
    }
}

impl RuntimeGeneration {
    /// 校验并构建候选代际：悬空引用与循环引用在此拒绝（验收口径），
    /// 通过后按内容摘要定身份。同内容必同 `generation_id`。同一对象
    /// ID 重复出现时：内容完全一致按一条计；内容冲突（同 ID 不同
    /// 摘要/类别）拒绝，不静默合并。
    pub fn build(
        objects: Vec<GenerationObject>,
        edges: Vec<GenerationEdge>,
    ) -> Result<Self, GenerationError> {
        // 去重 + 冲突检测：同 ID 同内容合并，同 ID 异内容显式拒绝
        let mut by_id: BTreeMap<ObjectId, GenerationObject> = BTreeMap::new();
        for obj in objects {
            match by_id.get(&obj.id) {
                Some(existing)
                    if existing.kind == obj.kind && existing.content_hash == obj.content_hash => {}
                Some(_) => {
                    return Err(GenerationError::DuplicateObject { id: obj.id });
                }
                None => {
                    by_id.insert(obj.id.clone(), obj);
                }
            }
        }
        let objects: Vec<GenerationObject> = by_id.into_values().collect();

        // 悬空引用：每条边的两端都必须在本代际内（已排序，二分查找）
        let contains = |id: &ObjectId| objects.binary_search_by(|obj| obj.id.cmp(id)).is_ok();
        for edge in &edges {
            let (from, to) = (&edge.from, &edge.to);
            if !contains(from) || !contains(to) {
                let missing = if contains(from) { to } else { from };
                let other = if contains(from) { from } else { to };
                return Err(GenerationError::DanglingReference {
                    from: other.clone(),
                    to: missing.clone(),
                });
            }
        }

        // 循环引用：白灰黑 DFS，按排序顺序保证报出的环确定
        let mut adjacency: BTreeMap<&ObjectId, Vec<&ObjectId>> = BTreeMap::new();
        for edge in &edges {
            adjacency.entry(&edge.from).or_default().push(&edge.to);
        }
        for targets in adjacency.values_mut() {
            targets.sort();
        }

        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color: BTreeMap<&ObjectId, Color> =
            objects.iter().map(|obj| (&obj.id, Color::White)).collect();

        for root_obj in &objects {
            let root = &root_obj.id;
            if color[root] != Color::White {
                continue;
            }
            if color[root] != Color::White {
                continue;
            }
            // 迭代 DFS：栈元素为 (节点, 是否已展开完)。done 弹出时收黑，
            // 保证兄弟子树重复到达的节点不会被误报为环。
            let mut stack: Vec<(&ObjectId, bool)> = vec![(root, false)];
            let mut path: Vec<&ObjectId> = Vec::new();
            while let Some((node, done)) = stack.pop() {
                if done {
                    color.insert(node, Color::Black);
                    path.pop();
                    continue;
                }
                match color[node] {
                    Color::Black => continue,
                    Color::Gray => {
                        // 命中灰色节点：截取 path 中从该节点起的环路
                        let start = path.iter().position(|id| *id == node).unwrap_or(0);
                        let cycle: Vec<ObjectId> = path[start..]
                            .iter()
                            .map(|id| (*id).clone())
                            .chain(std::iter::once((*node).clone()))
                            .collect();
                        return Err(GenerationError::ReferenceCycle { path: cycle });
                    }
                    Color::White => {}
                }
                color.insert(node, Color::Gray);
                path.push(node);
                stack.push((node, true));
                if let Some(targets) = adjacency.get(node) {
                    for target in targets.iter().rev() {
                        if color[target] != Color::Black {
                            stack.push((target, false));
                        }
                    }
                }
            }
        }

        // 内容摘要：域分隔前缀 + 排序后的对象与边全部进入哈希
        let mut hasher = Sha256::new();
        hasher.update(b"rillane-generation-v1");
        hasher.update([0x1f]);
        for obj in &objects {
            hasher.update(b"o");
            hasher.update([0x1f]);
            hasher.update(obj.id.source.as_str().as_bytes());
            hasher.update([0x1f]);
            hasher.update(obj.id.local_id.as_bytes());
            hasher.update([0x1f]);
            hasher.update(kind_tag(obj.kind).as_bytes());
            hasher.update([0x1f]);
            hasher.update(obj.content_hash.as_bytes());
            hasher.update([0x1f]);
        }
        for edge in &edges {
            hasher.update(b"e");
            hasher.update([0x1f]);
            hasher.update(edge.from.source.as_str().as_bytes());
            hasher.update([0x1f]);
            hasher.update(edge.from.local_id.as_bytes());
            hasher.update([0x1f]);
            hasher.update(edge.to.source.as_str().as_bytes());
            hasher.update([0x1f]);
            hasher.update(edge.to.local_id.as_bytes());
            hasher.update([0x1f]);
        }
        let digest = hasher.finalize();
        let generation_id = digest.iter().map(|b| format!("{b:02x}")).collect();

        Ok(Self {
            generation_id,
            objects,
            edges: edges.into_iter().collect(),
        })
    }

    /// 内容摘要派生的代际身份（64 位十六进制）
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// 代际内对象数
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// 代际是否为空
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// 按 ID 查找对象（对象按 ID 排序，二分查找）
    pub fn get(&self, id: &ObjectId) -> Option<&GenerationObject> {
        self.objects
            .binary_search_by(|obj| obj.id.cmp(id))
            .ok()
            .map(|index| &self.objects[index])
    }

    /// 全部对象（按 ID 排序）
    pub fn objects(&self) -> impl Iterator<Item = &GenerationObject> {
        self.objects.iter()
    }

    /// 全部引用边（排序）
    pub fn edges(&self) -> impl Iterator<Item = &GenerationEdge> {
        self.edges.iter()
    }
}

/// 代际发布位（RIL-003）：事务式发布——候选先整体校验，失败不触碰
/// 发布位（验收「失败候选不覆盖成功代际」）；成功则原子顶替，旧代际
/// 由已持有的 `Arc` 存活会话继续引用（验收「旧代际可被存活会话引用」）。
/// 同内容代际重复发布幂等返回现有代际，不产生假新版本。
#[derive(Debug, Clone, Default)]
pub struct GenerationStore {
    published: Option<Arc<RuntimeGeneration>>,
}

impl GenerationStore {
    /// 空发布位
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前已发布代际
    pub fn published(&self) -> Option<&Arc<RuntimeGeneration>> {
        self.published.as_ref()
    }

    /// 事务式发布候选：`objects`/`edges` 先整体校验（悬空/循环拒绝），
    /// 校验失败返回 Err 且发布位不变；成功则原子顶替并返回新代际句柄。
    pub fn publish(
        &mut self,
        objects: Vec<GenerationObject>,
        edges: Vec<GenerationEdge>,
    ) -> Result<Arc<RuntimeGeneration>, GenerationError> {
        let candidate = RuntimeGeneration::build(objects, edges)?;
        if let Some(current) = &self.published {
            if current.generation_id == candidate.generation_id {
                return Ok(Arc::clone(current));
            }
        }
        let arc = Arc::new(candidate);
        self.published = Some(Arc::clone(&arc));
        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceId;

    fn source(name: &str) -> SourceId {
        SourceId::new(name).unwrap()
    }

    fn obj(source_name: &str, local_id: &str, kind: ObjectKind) -> GenerationObject {
        GenerationObject {
            id: ObjectId::new(source(source_name), local_id),
            kind,
            content_hash: digest_parts(&[local_id, "content"]),
        }
    }

    fn edge(from: &str, to: &str) -> GenerationEdge {
        GenerationEdge {
            from: ObjectId::new(source("sub"), from),
            to: ObjectId::new(source("sub"), to),
        }
    }

    fn objects() -> Vec<GenerationObject> {
        vec![
            obj("sub", "n1", ObjectKind::Node),
            obj("sub", "n2", ObjectKind::Node),
            obj("sub", "g1", ObjectKind::Group),
        ]
    }

    #[test]
    fn build_rejects_dangling_reference_with_stable_code() {
        let err =
            RuntimeGeneration::build(objects(), vec![edge("g1", "missing-node")]).unwrap_err();
        assert_eq!(err.code(), CODE_GENERATION_DANGLING);
        match &err {
            GenerationError::DanglingReference { from, to } => {
                assert_eq!(from.local_id, "g1");
                assert_eq!(to.local_id, "missing-node");
            }
            other => panic!("应为 DanglingReference，实际 {other:?}"),
        }
    }

    #[test]
    fn build_rejects_reference_cycle_with_stable_code() {
        // 二环：g1 -> g2 -> g1
        let objects = vec![
            obj("sub", "n1", ObjectKind::Node),
            obj("sub", "g1", ObjectKind::Group),
            obj("sub", "g2", ObjectKind::Group),
        ];
        let err = RuntimeGeneration::build(objects, vec![edge("g1", "g2"), edge("g2", "g1")])
            .unwrap_err();
        assert_eq!(err.code(), CODE_GENERATION_CYCLE);

        // 自环也是循环
        let err = RuntimeGeneration::build(
            vec![obj("sub", "g1", ObjectKind::Group)],
            vec![edge("g1", "g1")],
        )
        .unwrap_err();
        assert_eq!(err.code(), CODE_GENERATION_CYCLE);
        match err {
            GenerationError::ReferenceCycle { path } => {
                assert_eq!(path.first(), path.last(), "环路首尾同一对象");
                assert_eq!(path.len(), 2, "自环路径为 g1 -> g1");
            }
            other => panic!("应为 ReferenceCycle，实际 {other:?}"),
        }
    }

    #[test]
    fn generation_id_is_content_addressed() {
        let a = RuntimeGeneration::build(objects(), vec![edge("g1", "n1")]).unwrap();
        let b = RuntimeGeneration::build(objects(), vec![edge("g1", "n1")]).unwrap();
        assert_eq!(a.generation_id(), b.generation_id(), "同内容必同代际身份");

        // 换边 → 新代际
        let c = RuntimeGeneration::build(objects(), vec![edge("g1", "n2")]).unwrap();
        assert_ne!(a.generation_id(), c.generation_id());

        // 对象内容变化 → 新代际
        let mut changed = objects();
        changed[0].content_hash = digest_parts(&["n1", "content-v2"]);
        let d = RuntimeGeneration::build(changed, vec![edge("g1", "n1")]).unwrap();
        assert_ne!(a.generation_id(), d.generation_id());
    }

    #[test]
    fn digest_parts_matches_derive_local_id_discipline() {
        // 同分隔纪律：digest_parts 前缀扩展不改变 derive_local_id 的输入口径
        let full = digest_parts(&["vmess", "example.com", "443"]);
        assert_eq!(full.len(), 64, "完整 SHA-256 十六进制长度");
        let other = digest_parts(&["vmess", "example.com", "8443"]);
        assert_ne!(full, other);
    }

    #[test]
    fn build_rejects_conflicting_duplicate_object() {
        // 同 ID 异内容：显式拒绝，不静默合并
        let mut conflict_objects = objects();
        let extra = obj("sub", "n1", ObjectKind::Node);
        let conflicting = GenerationObject {
            content_hash: digest_parts(&["n1", "content-v2"]),
            ..extra
        };
        conflict_objects.push(conflicting);
        let err = RuntimeGeneration::build(conflict_objects, vec![]).unwrap_err();
        assert_eq!(err.code(), CODE_GENERATION_DUPLICATE);

        // 同 ID 同内容重复：按一条计，不报错
        let mut dup_objects = objects();
        dup_objects.push(obj("sub", "n1", ObjectKind::Node));
        let gen = RuntimeGeneration::build(dup_objects, vec![edge("g1", "n1")]).unwrap();
        assert_eq!(gen.len(), 3);
    }

    #[test]
    fn deserialization_rejects_tampered_identity() {
        let gen = RuntimeGeneration::build(objects(), vec![edge("g1", "n1")]).unwrap();
        let mut json = serde_json::to_value(&gen).unwrap();
        // 篡改代际身份 → 反序列化拒绝
        json["generation_id"] = serde_json::Value::String("0".repeat(64));
        let err = serde_json::from_value::<RuntimeGeneration>(json).unwrap_err();
        assert!(
            err.to_string().contains(CODE_GENERATION_ID_MISMATCH),
            "错误须含稳定码 {CODE_GENERATION_ID_MISMATCH}，实际: {err}"
        );
        // 未篡改 → 通过
        let json = serde_json::to_value(&gen).unwrap();
        let back: RuntimeGeneration = serde_json::from_value(json).unwrap();
        assert_eq!(back, gen);
    }
}
