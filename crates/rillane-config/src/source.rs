//! 来源与诊断契约（RIL-002）：SourceSnapshot、来源位置、对象稳定 ID 与
//! CompatibilityDiagnostic。显示名可重复——跨来源同名对象靠 `(SourceId,
//! local_id)` 区分，永不冲突；无上游稳定 ID 时用内容摘要派生稳定映射。
//! 删除与改名经快照 diff 显式化（removed/renamed/added），不靠名字推断。
//!
//! 诊断按稳定原因码（`compat.unsupported` / `compat.lossy`）携带对象 ID、
//! 来源位置与可选字段路径——文案可演进，码与定位恒定。Clash/Mihomo 侧
//! 的损失清单（RIL-093 ConversionReport）在此契约上收敛，订阅解析仍只
//! 在 rillane-subscription 侧进行（内核不依赖 Clash 格式，RIL-001）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 稳定原因码：输入对象不被支持（该类语义无法保真）。
pub const CODE_COMPAT_UNSUPPORTED: &str = "compat.unsupported";
/// 稳定原因码：显式有损转换（语义降级，可用但与输入不等价）。
pub const CODE_COMPAT_LOSSY: &str = "compat.lossy";
/// 稳定原因码：来源标识非法。
pub const CODE_SOURCE_ID_INVALID: &str = "source.id.invalid";
/// 稳定原因码：快照来源不匹配（diff 的两侧须来自同一来源）。
pub const CODE_SOURCE_MISMATCH: &str = "source.mismatch";

/// 来源契约错误（RIL-002）：文案可演进，`code()` 恒定。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceContractError {
    /// 来源标识非法
    #[error("{CODE_SOURCE_ID_INVALID}: 来源标识 {raw:?} 非法: {reason}")]
    InvalidSourceId { raw: String, reason: &'static str },
    /// diff 两侧来源不同（一个来源的快照只与自身历史比较）
    #[error("{CODE_SOURCE_MISMATCH}: diff 须在同一来源内进行: {:?} vs {:?}", .expected, .actual)]
    SourceMismatch { expected: String, actual: String },
}

impl SourceContractError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            SourceContractError::InvalidSourceId { .. } => CODE_SOURCE_ID_INVALID,
            SourceContractError::SourceMismatch { .. } => CODE_SOURCE_MISMATCH,
        }
    }
}

/// 来源命名空间标识（RIL-002）：一个订阅/provider 一个 SourceId。显示名
/// 不是身份——同名节点跨来源共存靠来源命名空间隔离（验收「同名跨来源
/// 对象无冲突」）。用户可读、稳定、不含控制字符且不为空；上限 128 字节。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SourceId(String);

impl SourceId {
    /// 长度上限（字节）
    pub const MAX_LEN: usize = 128;

    /// 校验并构造来源标识
    pub fn new(raw: &str) -> Result<Self, SourceContractError> {
        if raw.is_empty() {
            return Err(SourceContractError::InvalidSourceId {
                raw: raw.to_string(),
                reason: "为空",
            });
        }
        if raw.len() > Self::MAX_LEN {
            return Err(SourceContractError::InvalidSourceId {
                raw: raw.to_string(),
                reason: "超过 128 字节上限",
            });
        }
        if raw.chars().any(char::is_control) {
            return Err(SourceContractError::InvalidSourceId {
                raw: raw.to_string(),
                reason: "含控制字符",
            });
        }
        Ok(SourceId(raw.to_string()))
    }

    /// 标识原文
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SourceId {
    type Error = SourceContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        SourceId::new(&value)
    }
}

impl From<SourceId> for String {
    fn from(id: SourceId) -> Self {
        id.0
    }
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 来源内稳定的对象身份（RIL-002）：`(来源, local_id)`。同一来源内
/// local_id 唯一；跨来源永不冲突（即使显示名相同）。Clash proxies 无
/// 上游稳定 ID，用 [`derive_local_id`] 从内容身份元组派生——改名（同
/// server/port、新显示名）得到同 ID，从而 diff 出 rename 而非删+增。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId {
    /// 所属来源命名空间
    pub source: SourceId,
    /// 来源内稳定本地 ID（上游 ID 或内容派生）
    pub local_id: String,
}

impl ObjectId {
    /// 构造对象 ID（local_id 直接采用上游稳定 ID 的场景）
    pub fn new(source: SourceId, local_id: impl Into<String>) -> Self {
        Self {
            source,
            local_id: local_id.into(),
        }
    }
}

/// 从内容身份元组派生来源内稳定 local_id（RIL-002）：SHA-256 前 16 个
/// 十六进制字符（64 位）。无上游 ID 时的稳定映射——同内容必同 ID；
/// 不同内容撞出同 ID 的概率在目录规模（万级）下可忽略，万一发生由
/// [`ObjectCatalog`] 的同来源重复诊断暴露，不静默合并。
pub fn derive_local_id(identity: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in identity {
        // '\x1f' 分隔避免相邻字段拼接歧义
        hasher.update(part.as_bytes());
        hasher.update([0x1f]);
    }
    let digest = hasher.finalize();
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// 对象类别（RIL-002）：目录内对象的粗粒度类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// 代理节点
    Node,
    /// 策略组
    Group,
    /// 规则集（rule-provider/RULE-SET 载体）
    RuleSet,
}

/// 来源位置（RIL-002）：定位来源文档内的对象/字段——来源 + 文档内指针
///（JSON Pointer 风格路径，如 `proxies/3`、`proxy-groups/0/proxies/1`）。
/// 内容摘要属于快照（[`SourceSnapshot::content_hash`]），不重复挂在每个
/// 位置上；诊断凭 `(location, 快照)` 即可对账到具体内容版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// 所属来源
    pub source: SourceId,
    /// 文档内指针（JSON Pointer 风格）
    pub pointer: String,
}

impl SourceLocation {
    /// 构造来源位置
    pub fn new(source: SourceId, pointer: impl Into<String>) -> Self {
        Self {
            source,
            pointer: pointer.into(),
        }
    }

    /// 追加路径段，返回新位置（链式定位字段用）
    pub fn join(&self, segment: &str) -> Self {
        Self {
            source: self.source.clone(),
            pointer: format!("{}/{}", self.pointer, segment),
        }
    }
}

/// 来源快照内的一个对象条目（RIL-002）：稳定 ID + 显示名 + 类别 + 位置。
/// 显示名仅面向用户展示；引用与 diff 一律走 ObjectId。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceObject {
    /// 稳定身份
    pub id: ObjectId,
    /// 类别
    pub kind: ObjectKind,
    /// 显示名（可重复，非身份）
    pub display_name: String,
    /// 来源文档内位置
    pub location: SourceLocation,
}

/// 一个来源的一次完整版本（RIL-002 / C09）：节点/规则集合的原子替换单元。
/// 记录解码后、解析前内容的 SHA-256（`content_hash`）与解析器版本——
/// 同内容+同解析器不构成新版本（不触发无意义发布）；解析器/本地策略
/// 变化仍可产生新代际。ETag/Last-Modified 只是缓存提示，不进入快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    /// 所属来源
    pub source: SourceId,
    /// 解码后、解析前内容的 SHA-256（十六进制）
    pub content_hash: String,
    /// 解析器版本（来源版本参与方之一）
    pub parser_version: u32,
    /// 获取时间（Unix 毫秒）
    pub fetched_at_unix_ms: u64,
    /// 本版本全部对象（原子替换：不在此列即已删除）
    pub objects: Vec<SourceObject>,
}

impl SourceSnapshot {
    /// 按来源内 local_id 查找对象
    pub fn find(&self, local_id: &str) -> Option<&SourceObject> {
        self.objects
            .iter()
            .find(|obj| obj.id.local_id == local_id)
    }

    /// 按显示名查找对象（可能多个——显示名非唯一身份）
    pub fn by_display_name(&self, name: &str) -> Vec<&SourceObject> {
        self.objects
            .iter()
            .filter(|obj| obj.display_name == name)
            .collect()
    }

    /// 内容摘要（SHA-256 十六进制，64 字符）
    pub fn hash_content(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 是否为同一来源版本（同内容 + 同解析器）：true = 重获取无新意，
    /// 不触发无意义发布（验收辅助口径；发布策略由 RIL-008 接入）
    pub fn is_same_version_as(&self, other: &Self) -> bool {
        self.source == other.source
            && self.content_hash == other.content_hash
            && self.parser_version == other.parser_version
    }

    /// 与同来源下一版快照 diff，显式给出删除/改名/新增（RIL-002 验收：
    /// 删除与改名语义明确）。改名 = 同 ObjectId、显示名变化；同显示名、
    /// 不同 ObjectId 是两个对象（增+删），不算改名——不靠名字猜身份。
    pub fn diff(&self, next: &Self) -> Result<SnapshotDiff, SourceContractError> {
        if self.source != next.source {
            return Err(SourceContractError::SourceMismatch {
                expected: self.source.as_str().to_string(),
                actual: next.source.as_str().to_string(),
            });
        }

        let old: BTreeMap<&str, &SourceObject> = self
            .objects
            .iter()
            .map(|obj| (obj.id.local_id.as_str(), obj))
            .collect();
        let new: BTreeMap<&str, &SourceObject> = next
            .objects
            .iter()
            .map(|obj| (obj.id.local_id.as_str(), obj))
            .collect();

        let mut diff = SnapshotDiff::default();
        for (local_id, old_obj) in &old {
            match new.get(local_id) {
                None => diff.removed.push(old_obj.id.clone()),
                Some(new_obj) if new_obj.display_name != old_obj.display_name => {
                    diff.renamed.push(ObjectRenamed {
                        id: old_obj.id.clone(),
                        old_name: old_obj.display_name.clone(),
                        new_name: new_obj.display_name.clone(),
                    });
                }
                Some(_) => diff.unchanged += 1,
            }
        }
        for (local_id, new_obj) in &new {
            if !old.contains_key(local_id) {
                diff.added.push(new_obj.id.clone());
            }
        }
        Ok(diff)
    }
}

/// 改名条目：同稳定 ID，显示名从旧到新。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRenamed {
    /// 稳定身份（不变）
    pub id: ObjectId,
    /// 旧显示名
    pub old_name: String,
    /// 新显示名
    pub new_name: String,
}

/// 快照 diff 结果（RIL-002）：删除/改名/新增全部显式列出。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// 新增对象的稳定 ID
    pub added: Vec<ObjectId>,
    /// 删除对象的稳定 ID（含用户选择恢复策略的输入，RIL-011 接入）
    pub removed: Vec<ObjectId>,
    /// 改名条目（同 ID、新显示名）
    pub renamed: Vec<ObjectRenamed>,
    /// 未变化对象数
    pub unchanged: usize,
}

/// 跨来源对象目录（RIL-002 / C10）：以 ObjectId 为主键聚合多来源快照。
/// 同名跨来源对象共存（键不同）；同来源内 local_id 重复——同一来源里
/// 两条内容相同身份的对象——按错误显式暴露，不静默合并。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectCatalog {
    objects: BTreeMap<ObjectId, SourceObject>,
}

impl ObjectCatalog {
    /// 空目录
    pub fn new() -> Self {
        Self::default()
    }

    /// 并入一个快照的全部对象
    pub fn merge_snapshot(&mut self, snapshot: &SourceSnapshot) -> Result<(), SourceContractError> {
        for object in &snapshot.objects {
            if let Some(existing) = self.objects.get(&object.id) {
                // 键 = (source, local_id)：能走到这里必然同来源同 ID
                return Err(SourceContractError::InvalidSourceId {
                    raw: format!(
                        "对象 {}({:?}) 与既有 {}({:?}) 同来源同 local_id",
                        object.display_name, object.id.local_id, existing.display_name, existing.id.local_id
                    ),
                    reason: "来源内稳定 ID 重复，须先诊断去重",
                });
            }
            self.objects.insert(object.id.clone(), object.clone());
        }
        Ok(())
    }

    /// 按稳定 ID 查找
    pub fn get(&self, id: &ObjectId) -> Option<&SourceObject> {
        self.objects.get(id)
    }

    /// 按显示名查找（跨来源同名全部返回——证明同名不冲突、可区分）
    pub fn by_display_name(&self, name: &str) -> Vec<&SourceObject> {
        self.objects
            .values()
            .filter(|obj| obj.display_name == name)
            .collect()
    }

    /// 目录规模
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// 目录是否为空
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

/// 兼容性诊断（RIL-002 / C13）：输入对象 → 精确的支持/不支持/有损报告。
/// 码（`compat.unsupported` / `compat.lossy`）与定位（对象 ID + 来源位置
/// + 可选字段）是机器口径，恒定；`detail` 文案可演进，不作匹配依据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityDiagnostic {
    /// 稳定原因码
    pub code: &'static str,
    /// 涉及对象的稳定 ID（可缺——来源级问题无具体对象）
    pub object: Option<ObjectId>,
    /// 来源位置（定位对象在来源文档中的位置）
    pub location: SourceLocation,
    /// 字段路径（定位对象内具体字段；可缺）
    pub field: Option<String>,
    /// 人读细节（不作匹配依据）
    pub detail: String,
}

impl CompatibilityDiagnostic {
    /// 不支持诊断：该输入对象的语义无法保真，整体不采纳
    pub fn unsupported(
        object: Option<ObjectId>,
        location: SourceLocation,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code: CODE_COMPAT_UNSUPPORTED,
            object,
            location,
            field: None,
            detail: detail.into(),
        }
    }

    /// 有损诊断：语义降级（可用但与输入不等价），可随宽松模式放行
    pub fn lossy(
        object: Option<ObjectId>,
        location: SourceLocation,
        field: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code: CODE_COMPAT_LOSSY,
            object,
            location,
            field,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str) -> SourceId {
        SourceId::new(name).unwrap()
    }

    #[test]
    fn source_id_rejects_invalid() {
        assert!(SourceId::new("").is_err());
        assert!(SourceId::new("bad\u{7}id").is_err());
        assert!(SourceId::new(&"x".repeat(129)).is_err());
        let err = SourceId::new("").unwrap_err();
        assert_eq!(err.code(), CODE_SOURCE_ID_INVALID);
    }

    #[test]
    fn derive_local_id_stable_and_content_addressed() {
        let a = derive_local_id(&["vmess", "example.com", "443"]);
        let b = derive_local_id(&["vmess", "example.com", "443"]);
        let c = derive_local_id(&["vmess", "example.com", "8443"]);
        assert_eq!(a, b, "同内容身份必同 ID");
        assert_ne!(a, c, "不同内容身份不同 ID");
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn diff_rejects_cross_source() {
        let s1 = SourceSnapshot {
            source: source("a"),
            content_hash: "h1".into(),
            parser_version: 1,
            fetched_at_unix_ms: 0,
            objects: vec![],
        };
        let s2 = SourceSnapshot {
            source: source("b"),
            ..s1.clone()
        };
        let err = s1.diff(&s2).unwrap_err();
        assert_eq!(err.code(), CODE_SOURCE_MISMATCH);
    }

    #[test]
    fn snapshot_version_identity_ignores_fetch_time() {
        let s1 = SourceSnapshot {
            source: source("a"),
            content_hash: "h".into(),
            parser_version: 3,
            fetched_at_unix_ms: 1,
            objects: vec![],
        };
        let mut s2 = s1.clone();
        s2.fetched_at_unix_ms = 999;
        assert!(s1.is_same_version_as(&s2), "同内容同解析器=同版本");
        s2.parser_version = 4;
        assert!(!s1.is_same_version_as(&s2), "解析器变化产生新版本");
    }
}
