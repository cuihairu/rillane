//! ConfigProposal 临时状态存储（RIL-073）：提案生命周期的服务端暂存面。
//! 提案 = 一份待审配置补丁 + 其绑定的基础代际与内容哈希 + 所有者、
//! 范围与 TTL。读取是守卫式的：未知 ID、跨所有者、过期、基础内容已变化
//! 四种情形逐因显式拒绝（稳定原因码），绝不静默回落。
//!
//! 资源边界：存储容量有硬上限；插入时先清扫过期项再判容量——满员且无
//! 过期可回收时以 `proposal.capacity` 显式拒绝（不静默逐出活提案）。
//! 时间由调用方注入（纯存储、无时钟依赖），ID 随机性由 [`new_proposal_id`]
//! 提供（uuid v4，122 位随机——不可猜测性是提案面的授权边界）。
//!
//! 拒绝顺序契约：`unknown → foreign → expired → base_changed`。跨所有者
//! 判定先于过期/哈希判定——非所有者探测他人提案只能得到 `foreign`，
//! 无法借响应差异推断其存活状态或基础是否变化。
//!
//! 接线边界：本模块只定义存储与守卫；提案的验证/预览（RIL-074）、授权
//! 绑定（RIL-075）、Apply 事务（RIL-076）与 HTTP/CLI/MCP 表面在各自任务
//! 接入。

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

/// 稳定原因码：提案 ID 不存在（或已被清扫/取消）。
pub const CODE_PROPOSAL_UNKNOWN: &str = "proposal.unknown";
/// 稳定原因码：调用者不是提案所有者（跨调用者读取拒绝）。
pub const CODE_PROPOSAL_FOREIGN: &str = "proposal.foreign";
/// 稳定原因码：提案已过 TTL。
pub const CODE_PROPOSAL_EXPIRED: &str = "proposal.expired";
/// 稳定原因码：基础内容已变化（base_hash ≠ 当前内容哈希）——提案失效。
pub const CODE_PROPOSAL_BASE_CHANGED: &str = "proposal.base_changed";
/// 稳定原因码：存储已满且无过期项可回收。
pub const CODE_PROPOSAL_CAPACITY: &str = "proposal.capacity";
/// 稳定原因码：范围面非法（空 / 超项数 / 超长 / 控制字符）。
pub const CODE_PROPOSAL_SCOPE_INVALID: &str = "proposal.scope.invalid";
/// 稳定原因码：TTL 非法（0 或超上限）。
pub const CODE_PROPOSAL_TTL_INVALID: &str = "proposal.ttl.invalid";
/// 稳定原因码：其余输入字段非法（空 / 超长 / 控制字符 / patch 非对象）。
pub const CODE_PROPOSAL_INPUT_INVALID: &str = "proposal.input.invalid";
/// 稳定原因码：提案 ID 冲突（概率上仅源于实现缺陷——调用方须换 ID 重试）。
pub const CODE_PROPOSAL_ID_CLASH: &str = "proposal.id.clash";

/// 存储容量硬上限（临时状态——不是持久队列；满员拒绝而非逐出活提案）。
pub const PROPOSAL_STORE_CAP: usize = 64;
/// TTL 上限（毫秒）：临时状态不无限期占位。
pub const PROPOSAL_MAX_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// owner / base_generation 等标签字段的最大字符数。
pub const PROPOSAL_MAX_LABEL_CHARS: usize = 128;
/// base_hash 字段的最大字符数（规范 SHA-256 十六进制为 64）。
pub const PROPOSAL_MAX_HASH_CHARS: usize = 128;
/// 范围条目数上限。
pub const PROPOSAL_MAX_SCOPE_ITEMS: usize = 16;
/// 单条范围条目的最大字符数。
pub const PROPOSAL_MAX_SCOPE_ITEM_CHARS: usize = 64;
/// 提案 ID 的最大字符数（uuid simple 形为 32）。
pub const PROPOSAL_MAX_ID_CHARS: usize = 64;

/// 生成不可猜测的提案 ID（uuid v4 simple 形：32 位小写十六进制，
/// 122 位随机量）。ID 的随机性是提案面授权边界的一半——另一半是
/// 所有者绑定（见 [`ProposalStore::read`] 拒绝顺序契约）。
pub fn new_proposal_id() -> String {
    Uuid::new_v4().simple().to_string()
}

/// 一份待应用的配置提案（RIL-073 存储形）：补丁本体 + 其成立前提
/// （基础代际与内容哈希）+ 归属与授权面（所有者、范围）+ 生命周期。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigProposal {
    /// 不可猜测 ID（[`new_proposal_id`] 产出）
    pub id: String,
    /// 提案成立时假设的基础代际 ID
    pub base_generation: String,
    /// 提案成立时假设的基础内容摘要（读取时与当前内容哈希比对——
    /// 内容已变即失效，`proposal.base_changed`）
    pub base_hash: String,
    /// 所有者（调用方提供的不透明标签；读取/取消须逐一匹配）
    pub owner: String,
    /// 授权范围（提案允许触碰的配置段名；空面非法）
    pub scope: Vec<String>,
    /// 待应用补丁（JSON 对象；形状验证归 RIL-074）
    pub patch: serde_json::Value,
    /// 创建时刻（调用方时钟，毫秒）
    pub created_ms: u64,
    /// 过期时刻（创建 + TTL；到达即失效）
    pub expires_ms: u64,
}

/// 创建入参（[`ProposalStore::create`]）：ID 单独传（调用方经
/// [`new_proposal_id`] 生成，测试可注确定性 ID）。
#[derive(Debug, Clone, PartialEq)]
pub struct ProposalInput {
    pub base_generation: String,
    pub base_hash: String,
    pub owner: String,
    pub scope: Vec<String>,
    pub patch: serde_json::Value,
    /// 存活时长（毫秒；1..=[`PROPOSAL_MAX_TTL_MS`]）
    pub ttl_ms: u64,
}

/// 存储错误（文案可演进，`code()` 恒定）。读取侧拒绝以
/// [`ProposalRead::Rejected`] 的码承载；本枚举覆盖创建与取消两写路径。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalStoreError {
    /// 提案不存在（或已被清扫/取消）
    #[error("{CODE_PROPOSAL_UNKNOWN}: 提案不存在或已被回收/取消")]
    Unknown,
    /// 调用者不是提案所有者
    #[error("{CODE_PROPOSAL_FOREIGN}: 调用者不是提案所有者")]
    Foreign,
    /// 提案已过期
    #[error("{CODE_PROPOSAL_EXPIRED}: 提案已过期")]
    Expired,
    /// 存储已满且无过期项可回收
    #[error("{CODE_PROPOSAL_CAPACITY}: 提案存储已满且无过期项可回收")]
    Capacity,
    /// 范围面非法
    #[error(
        "{CODE_PROPOSAL_SCOPE_INVALID}: 提案范围非法（非空、≤16 项、每项 ≤64 字符、无控制字符）"
    )]
    ScopeInvalid,
    /// TTL 非法
    #[error("{CODE_PROPOSAL_TTL_INVALID}: TTL 非法（须 1..={PROPOSAL_MAX_TTL_MS} 毫秒）")]
    TtlInvalid,
    /// 其余输入字段非法（field 点名字段）
    #[error("{CODE_PROPOSAL_INPUT_INVALID}: 提案字段 {field:?} 非法（空 / 超长 / 含控制字符 / patch 非对象）")]
    InputInvalid {
        /// 点名的非法字段（id / base_generation / base_hash / owner / patch）
        field: &'static str,
    },
    /// 提案 ID 冲突
    #[error("{CODE_PROPOSAL_ID_CLASH}: 提案 ID 冲突（换 ID 重试）")]
    IdClash,
}

impl ProposalStoreError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            ProposalStoreError::Unknown => CODE_PROPOSAL_UNKNOWN,
            ProposalStoreError::Foreign => CODE_PROPOSAL_FOREIGN,
            ProposalStoreError::Expired => CODE_PROPOSAL_EXPIRED,
            ProposalStoreError::Capacity => CODE_PROPOSAL_CAPACITY,
            ProposalStoreError::ScopeInvalid => CODE_PROPOSAL_SCOPE_INVALID,
            ProposalStoreError::TtlInvalid => CODE_PROPOSAL_TTL_INVALID,
            ProposalStoreError::InputInvalid { .. } => CODE_PROPOSAL_INPUT_INVALID,
            ProposalStoreError::IdClash => CODE_PROPOSAL_ID_CLASH,
        }
    }
}

/// 守卫式读取结果（[`ProposalStore::read`]）：有效返回提案副本；拒绝
/// 携带稳定原因码（`unknown / foreign / expired / base_changed`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalRead {
    Valid(ConfigProposal),
    Rejected {
        /// 稳定原因码（CODE_PROPOSAL_UNKNOWN / FOREIGN / EXPIRED / BASE_CHANGED）
        code: &'static str,
    },
}

/// 提案存储（RIL-073）：有界 HashMap + 调用方供钟的清扫。纯存储面、
/// 无时钟无线程依赖——并发归属在守护进程侧包装（与采集器/TTL 同纪律）。
#[derive(Debug, Default)]
pub struct ProposalStore {
    entries: HashMap<String, ConfigProposal>,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前存活提案数（含未清扫的过期项——过期项在被读取时仍显式答
    /// `expired`，计数随清扫下降）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 登记一份提案。先清扫过期项再判容量——满员时回收过期项腾位；
    /// 仍满则 `proposal.capacity` 显式拒绝，绝不逐出活提案。
    pub fn create(
        &mut self,
        id: String,
        input: ProposalInput,
        now_ms: u64,
    ) -> Result<ConfigProposal, ProposalStoreError> {
        validate_label(&id, PROPOSAL_MAX_ID_CHARS)
            .map_err(|_| ProposalStoreError::InputInvalid { field: "id" })?;
        validate_label(&input.base_generation, PROPOSAL_MAX_LABEL_CHARS).map_err(|_| {
            ProposalStoreError::InputInvalid {
                field: "base_generation",
            }
        })?;
        validate_label(&input.base_hash, PROPOSAL_MAX_HASH_CHARS)
            .map_err(|_| ProposalStoreError::InputInvalid { field: "base_hash" })?;
        validate_label(&input.owner, PROPOSAL_MAX_LABEL_CHARS)
            .map_err(|_| ProposalStoreError::InputInvalid { field: "owner" })?;
        validate_scope(&input.scope)?;
        if !input.patch.is_object() {
            return Err(ProposalStoreError::InputInvalid { field: "patch" });
        }
        if input.ttl_ms == 0 || input.ttl_ms > PROPOSAL_MAX_TTL_MS {
            return Err(ProposalStoreError::TtlInvalid);
        }

        self.sweep(now_ms);
        if self.entries.len() >= PROPOSAL_STORE_CAP {
            return Err(ProposalStoreError::Capacity);
        }
        if self.entries.contains_key(&id) {
            return Err(ProposalStoreError::IdClash);
        }

        let proposal = ConfigProposal {
            id: id.clone(),
            base_generation: input.base_generation,
            base_hash: input.base_hash,
            owner: input.owner,
            scope: input.scope,
            patch: input.patch,
            created_ms: now_ms,
            expires_ms: now_ms.saturating_add(input.ttl_ms),
        };
        self.entries.insert(id, proposal.clone());
        Ok(proposal)
    }

    /// 守卫式读取（拒绝顺序契约：unknown → foreign → expired →
    /// base_changed——非所有者得不到任何状态侧信道）。`live_hash` 是
    /// 调用方当前计算的内容摘要：与提案登记的 `base_hash` 不一致即
    /// 内容已变，提案失效。
    pub fn read(&self, id: &str, owner: &str, now_ms: u64, live_hash: &str) -> ProposalRead {
        let Some(proposal) = self.entries.get(id) else {
            return ProposalRead::Rejected {
                code: CODE_PROPOSAL_UNKNOWN,
            };
        };
        if proposal.owner != owner {
            return ProposalRead::Rejected {
                code: CODE_PROPOSAL_FOREIGN,
            };
        }
        if now_ms >= proposal.expires_ms {
            return ProposalRead::Rejected {
                code: CODE_PROPOSAL_EXPIRED,
            };
        }
        if proposal.base_hash != live_hash {
            return ProposalRead::Rejected {
                code: CODE_PROPOSAL_BASE_CHANGED,
            };
        }
        ProposalRead::Valid(proposal.clone())
    }

    /// 所有者检查式取消（提前释放——不等 TTL）。拒绝顺序同 [`read`]：
    /// 非所有者对他人提案的取消只得到 `foreign`。过期项取消按已失效
    /// 处置：显式答 `expired` 并顺带回收该条目。哈希比对对取消无意义
    /// ——本路径不比较 `base_hash`（取消不看内容前提）。
    pub fn cancel(&mut self, id: &str, owner: &str, now_ms: u64) -> Result<(), ProposalStoreError> {
        let Some(proposal) = self.entries.get(id) else {
            return Err(ProposalStoreError::Unknown);
        };
        if proposal.owner != owner {
            return Err(ProposalStoreError::Foreign);
        }
        if now_ms >= proposal.expires_ms {
            // 过期项顺带回收——取消者是所有者，回收无泄露面
            self.entries.remove(id);
            return Err(ProposalStoreError::Expired);
        }
        self.entries.remove(id);
        Ok(())
    }

    /// 清扫过期项，返回回收数。
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, p| now_ms < p.expires_ms);
        before - self.entries.len()
    }

    /// 范围守卫（RIL-074/075/076 消费）：守卫式读取通过后判断提案是否
    /// 允许触碰 `section`。读取被拒时原码透传（Err）。
    pub fn covers(
        &self,
        id: &str,
        owner: &str,
        now_ms: u64,
        live_hash: &str,
        section: &str,
    ) -> Result<bool, &'static str> {
        match self.read(id, owner, now_ms, live_hash) {
            ProposalRead::Valid(proposal) => Ok(proposal.scope.iter().any(|s| s == section)),
            ProposalRead::Rejected { code } => Err(code),
        }
    }

    /// 事务内窥视（RIL-076 消费）：只做所有者与存活性守卫（unknown →
    /// foreign → expired），不比 `base_hash`——版本前置检查由消费方
    /// 自办（apply 以独立稳定码区分代际冲突与内容冲突，见
    /// `apply.base.conflict` / `apply.hash.conflict`）。
    pub fn peek(
        &self,
        id: &str,
        owner: &str,
        now_ms: u64,
    ) -> Result<&ConfigProposal, &'static str> {
        let Some(proposal) = self.entries.get(id) else {
            return Err(CODE_PROPOSAL_UNKNOWN);
        };
        if proposal.owner != owner {
            return Err(CODE_PROPOSAL_FOREIGN);
        }
        if now_ms >= proposal.expires_ms {
            return Err(CODE_PROPOSAL_EXPIRED);
        }
        Ok(proposal)
    }
}

fn validate_label(field: &str, max_chars: usize) -> Result<(), &'static str> {
    if field.is_empty() || field.chars().count() > max_chars {
        return Err(CODE_PROPOSAL_INPUT_INVALID);
    }
    if field.chars().any(char::is_control) {
        return Err(CODE_PROPOSAL_INPUT_INVALID);
    }
    Ok(())
}

fn validate_scope(scope: &[String]) -> Result<(), ProposalStoreError> {
    if scope.is_empty() || scope.len() > PROPOSAL_MAX_SCOPE_ITEMS {
        return Err(ProposalStoreError::ScopeInvalid);
    }
    for item in scope {
        if item.is_empty()
            || item.chars().count() > PROPOSAL_MAX_SCOPE_ITEM_CHARS
            || item.chars().any(char::is_control)
        {
            return Err(ProposalStoreError::ScopeInvalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod proposal_tests {
    use super::*;
    use crate::generations::digest_parts;

    fn input() -> ProposalInput {
        ProposalInput {
            base_generation: digest_parts(&["gen-1"]),
            base_hash: digest_parts(&["config-v1"]),
            owner: "cli:local".to_string(),
            scope: vec!["routing".to_string(), "dns".to_string()],
            patch: serde_json::json!({"routing": {"default_node": "proxy"}}),
            ttl_ms: 60_000,
        }
    }

    fn input_with_ttl(ttl_ms: u64) -> ProposalInput {
        ProposalInput { ttl_ms, ..input() }
    }

    #[test]
    fn proposal_ids_are_unguessable() {
        let a = new_proposal_id();
        let b = new_proposal_id();
        assert_ne!(a, b, "两次生成必须不同");
        assert_eq!(a.len(), 32, "uuid simple 形为 32 字符");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "ID 只含小写十六进制: {a}"
        );
    }

    #[test]
    fn create_and_read_roundtrip() {
        let mut store = ProposalStore::new();
        let created = store
            .create(new_proposal_id(), input(), 1_000)
            .expect("合法输入应登记成功");
        assert_eq!(created.created_ms, 1_000);
        assert_eq!(created.expires_ms, 61_000);
        assert_eq!(store.len(), 1);

        let live_hash = digest_parts(&["config-v1"]);
        match store.read(&created.id, "cli:local", 2_000, &live_hash) {
            ProposalRead::Valid(p) => {
                assert_eq!(p, created, "读取返回登记原文");
                assert_eq!(p.scope, vec!["routing".to_string(), "dns".to_string()]);
            }
            ProposalRead::Rejected { code } => panic!("有效读取被拒: {code}"),
        }
    }

    #[test]
    fn unknown_id_reads_explicit() {
        let store = ProposalStore::new();
        match store.read("nonexistent", "cli:local", 0, "h") {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_UNKNOWN),
            ProposalRead::Valid(_) => panic!("未知 ID 不得有效"),
        }
    }

    /// 跨调用者读取拒绝且不泄露状态：构造一份同时过期 + 基础已变的
    /// 提案，错误所有者读到的仍是 `foreign`——响应差异不构成侧信道。
    #[test]
    fn foreign_owner_rejected_without_state_leak() {
        let mut store = ProposalStore::new();
        let p = store.create(new_proposal_id(), input(), 0).expect("登记");
        // 过期（now ≥ expires）且内容已变（live_hash ≠ base_hash）
        let changed = digest_parts(&["config-v2"]);
        match store.read(&p.id, "attacker", p.expires_ms, &changed) {
            ProposalRead::Rejected { code } => {
                assert_eq!(code, CODE_PROPOSAL_FOREIGN, "非所有者只见 foreign");
            }
            ProposalRead::Valid(_) => panic!("非所有者不得有效"),
        }
        // 同所有者同一时刻才看到 expired
        match store.read(&p.id, "cli:local", p.expires_ms, &changed) {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_EXPIRED),
            ProposalRead::Valid(_) => panic!("过期提案不得有效"),
        }
    }

    /// 验收「内容修改失效」：基础内容哈希与当前不一致即失效。
    #[test]
    fn base_change_invalidates_proposal() {
        let mut store = ProposalStore::new();
        let p = store.create(new_proposal_id(), input(), 0).expect("登记");
        let changed = digest_parts(&["config-v2"]);
        match store.read(&p.id, "cli:local", 1, &changed) {
            ProposalRead::Rejected { code } => {
                assert_eq!(code, CODE_PROPOSAL_BASE_CHANGED);
            }
            ProposalRead::Valid(_) => panic!("内容已变不得有效"),
        }
        // 恢复一致哈希（如回滚后）→ 恢复有效
        let restored = digest_parts(&["config-v1"]);
        assert!(matches!(
            store.read(&p.id, "cli:local", 1, &restored),
            ProposalRead::Valid(_)
        ));
    }

    /// 验收「过期拒绝 + 回收」：到期读取显式 `expired`；sweep 回收后
    /// 容量释放，条目归 unknown。
    #[test]
    fn expired_read_rejected_then_sweep_reclaims() {
        let mut store = ProposalStore::new();
        let p = store
            .create(new_proposal_id(), input_with_ttl(1_000), 0)
            .expect("登记");
        match store.read(&p.id, "cli:local", 1_000, "h") {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_EXPIRED),
            ProposalRead::Valid(_) => panic!("到达 expires_ms 即过期"),
        }
        assert_eq!(store.sweep(1_000), 1, "清扫回收过期项");
        assert!(store.is_empty());
        match store.read(&p.id, "cli:local", 1_000, "h") {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_UNKNOWN),
            ProposalRead::Valid(_) => panic!("回收后不得有效"),
        }
    }

    /// 验收「容量和回收上限」：容量硬上限、满员显式拒绝（不逐出活提案）、
    /// 插入时先回收过期项腾位。
    #[test]
    fn capacity_bounded_with_expired_reclaim() {
        let mut store = ProposalStore::new();
        // 前 CAP-1 份长寿命
        let mut durable_id = String::new();
        for i in 0..PROPOSAL_STORE_CAP - 1 {
            let p = store
                .create(new_proposal_id(), input_with_ttl(60_000), 0)
                .unwrap_or_else(|e| panic!("第 {i} 份应登记: {e}"));
            durable_id = p.id;
        }
        // 第 CAP 份短寿命（expires = 1_000）
        let short = store
            .create(new_proposal_id(), input_with_ttl(1_000), 0)
            .expect("第 CAP 份应登记");
        assert_eq!(store.len(), PROPOSAL_STORE_CAP);

        // 满：显式拒绝（即使输入合法），存量不变
        let err = store
            .create(new_proposal_id(), input_with_ttl(1_000), 0)
            .expect_err("满员须拒绝");
        assert_eq!(err.code(), CODE_PROPOSAL_CAPACITY);
        assert_eq!(store.len(), PROPOSAL_STORE_CAP, "拒绝不改变存量");

        // 过期后插入：先回收短寿命那份再腾位（活提案不被逐出）
        let next = store
            .create(new_proposal_id(), input_with_ttl(60_000), 1_000)
            .expect("过期回收后应腾位");
        assert_eq!(store.len(), PROPOSAL_STORE_CAP, "回收 1 份 + 新增 1 份");
        match store.read(&short.id, "cli:local", 1_000, "h") {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_UNKNOWN),
            ProposalRead::Valid(_) => panic!("被回收项不得有效"),
        }
        assert!(matches!(
            store.read(
                &durable_id,
                "cli:local",
                1_000,
                &digest_parts(&["config-v1"])
            ),
            ProposalRead::Valid(_)
        ));
        assert!(matches!(
            store.read(&next.id, "cli:local", 1_000, &digest_parts(&["config-v1"])),
            ProposalRead::Valid(_)
        ));
    }

    /// 输入校验逐字段点名：空/超长/控制字符、范围面、TTL 值域、patch 形状；
    /// 被拒输入不留痕。
    #[test]
    fn create_rejects_invalid_inputs() {
        let mut store = ProposalStore::new();

        let mut bad = input();
        bad.owner = String::new();
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_INPUT_INVALID
        );

        let mut bad = input();
        bad.base_generation = "x".repeat(200);
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_INPUT_INVALID
        );

        let mut bad = input();
        bad.owner = "cli\u{0}local".to_string();
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_INPUT_INVALID
        );

        let mut bad = input();
        bad.scope = Vec::new();
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_SCOPE_INVALID
        );

        let mut bad = input();
        bad.scope = vec!["x\u{7}".to_string()];
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_SCOPE_INVALID
        );

        let mut bad = input();
        bad.ttl_ms = 0;
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_TTL_INVALID
        );

        let mut bad = input();
        bad.ttl_ms = PROPOSAL_MAX_TTL_MS + 1;
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_TTL_INVALID
        );

        let mut bad = input();
        bad.patch = serde_json::json!("not-an-object");
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_INPUT_INVALID
        );

        let mut bad = input();
        bad.patch = serde_json::json!(null);
        assert_eq!(
            store
                .create(new_proposal_id(), bad, 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_INPUT_INVALID
        );

        assert!(store.is_empty(), "全部被拒的输入不得留痕");
    }

    /// ID 冲突显式拒绝（概率上仅源于实现缺陷——不静默覆盖既有提案）。
    #[test]
    fn duplicate_id_rejected() {
        let mut store = ProposalStore::new();
        let p = store
            .create("fixed-id".to_string(), input(), 0)
            .expect("首次登记");
        let err = store
            .create("fixed-id".to_string(), input(), 0)
            .expect_err("重复 ID 须拒绝");
        assert_eq!(err.code(), CODE_PROPOSAL_ID_CLASH);
        // 原提案内容不被覆盖
        assert!(matches!(
            store.read(&p.id, "cli:local", 1, &digest_parts(&["config-v1"])),
            ProposalRead::Valid(_)
        ));
    }

    /// 取消是所有者检查式的：非所有者取消他人提案只得 `foreign` 且提案
    /// 存活；所有者取消即释放容量；过期项取消按已失效处置（回收且显式
    /// `expired`）；未知 ID 显式 `unknown`。
    #[test]
    fn cancel_is_owner_checked() {
        let mut store = ProposalStore::new();
        let p = store
            .create(new_proposal_id(), input_with_ttl(1_000), 0)
            .expect("登记");

        // 非所有者取消 → foreign，提案仍在
        assert_eq!(
            store.cancel(&p.id, "attacker", 1).err().unwrap().code(),
            CODE_PROPOSAL_FOREIGN
        );
        assert_eq!(store.len(), 1);

        // 所有者取消 → 释放
        store.cancel(&p.id, "cli:local", 1).expect("所有者取消");
        assert!(store.is_empty());
        match store.read(&p.id, "cli:local", 1, "h") {
            ProposalRead::Rejected { code } => assert_eq!(code, CODE_PROPOSAL_UNKNOWN),
            ProposalRead::Valid(_) => panic!("取消后不得有效"),
        }

        // 过期项取消：按已失效处置（回收 + expired 显式），不复活
        let q = store
            .create(new_proposal_id(), input_with_ttl(1_000), 0)
            .expect("登记");
        assert_eq!(
            store
                .cancel(&q.id, "cli:local", 2_000)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_EXPIRED
        );
        assert!(store.is_empty(), "过期项取消顺带回收");

        // 未知 ID 显式 unknown
        assert_eq!(
            store
                .cancel("nonexistent", "cli:local", 0)
                .err()
                .unwrap()
                .code(),
            CODE_PROPOSAL_UNKNOWN
        );
    }

    /// 范围守卫：有效提案逐段判定；读取被拒时原码透传。
    #[test]
    fn covers_checks_scope_owner_and_expiry() {
        let mut store = ProposalStore::new();
        let p = store.create(new_proposal_id(), input(), 0).expect("登记");
        let hash = digest_parts(&["config-v1"]);

        assert!(store
            .covers(&p.id, "cli:local", 1, &hash, "routing")
            .expect("有效提案应答范围判定"));
        assert!(!store
            .covers(&p.id, "cli:local", 1, &hash, "egress")
            .expect("有效提案应答范围判定"));
        assert_eq!(
            store
                .covers(&p.id, "attacker", 1, &hash, "routing")
                .unwrap_err(),
            CODE_PROPOSAL_FOREIGN
        );
        assert_eq!(
            store
                .covers(&p.id, "cli:local", p.expires_ms, &hash, "routing")
                .unwrap_err(),
            CODE_PROPOSAL_EXPIRED
        );
    }

    /// 事务内窥视（RIL-076 消费）：不比哈希——版本前置检查归消费方；
    /// unknown → foreign → expired 守卫序与 read 一致。
    #[test]
    fn peek_guards_owner_and_expiry_without_hash() {
        let mut store = ProposalStore::new();
        let p = store.create(new_proposal_id(), input(), 0).expect("登记");

        // 有效：哈希不匹配也照常返回本体（前置检查归 apply 面）
        let peeked = store.peek(&p.id, "cli:local", 1).expect("应窥视到本体");
        assert_eq!(peeked.base_hash, digest_parts(&["config-v1"]));
        assert_eq!(peeked.owner, "cli:local");

        assert_eq!(
            store.peek("missing", "cli:local", 1).unwrap_err(),
            CODE_PROPOSAL_UNKNOWN
        );
        assert_eq!(
            store.peek(&p.id, "attacker", 1).unwrap_err(),
            CODE_PROPOSAL_FOREIGN
        );
        assert_eq!(
            store.peek(&p.id, "cli:local", p.expires_ms).unwrap_err(),
            CODE_PROPOSAL_EXPIRED
        );
    }
}
