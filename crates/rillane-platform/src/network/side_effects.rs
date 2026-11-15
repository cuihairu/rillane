//! 系统副作用计划/补偿契约（RIL-018）：路由/DNS/防火墙变更统一进变更
//! 日志（journal）。每条记录带**所有权**——`PreExisting`（实例启动前
//! 已存在的系统配置：只观察登记，永不撤销）与 `Owned`（本实例创建/
//! 修改：可撤销，撤销动作显式携带）。撤销计划只包含本实例（同 owner）
//! 的已应用条目并按逆序回放；所有撤销动作按幂等契约解释（目标不存在
//! 视为已撤销；DNS 撤销是**还原先前内容**而非删除——已有系统配置不
//! 被误删）。任一步 apply 失败时，执行方只需对已成功条目取
//! [`SideEffectJournal::rollback_plan`] 逆序回放，失败步骤从未入日志。
//!
//! 接线边界：本模块是纯契约（零 OS 调用、零进程执行）；Linux 侧 argv
//! 构造与执行在 [`super::linux`]（TUN 逃逸面现有 `AppliedStep` 日志在
//! RIL-019 配置发布协调器接线时收敛到本契约）。

/// 稳定原因码：试图撤销非本实例所有（他人 Owned 或 PreExisting）的条目。
pub const CODE_SIDE_EFFECT_FOREIGN: &str = "side_effect.foreign";
/// 稳定原因码：日志中不存在该条目。
pub const CODE_SIDE_EFFECT_UNKNOWN: &str = "side_effect.unknown";

/// 变更涉及的系统面（RIL-018）。`as_str()` 是机器口径，恒定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemArea {
    /// 路由表
    Route,
    /// DNS 配置（resolv.conf 等）
    Dns,
    /// 防火墙规则
    Firewall,
}

impl SystemArea {
    /// 机器口径（恒定字符串）
    pub fn as_str(self) -> &'static str {
        match self {
            SystemArea::Route => "route",
            SystemArea::Dns => "dns",
            SystemArea::Firewall => "firewall",
        }
    }
}

/// 所有权（RIL-018 验收核心）：撤销只针对 `Owned` 且 owner 匹配的条目；
/// `PreExisting` 是启动时观察登记的既有系统配置，永不撤销。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// 本实例创建/修改——可由本实例撤销
    Owned,
    /// 实例启动前已存在——只登记审计，任何撤销路径都不得触碰
    PreExisting,
}

/// 撤销动作（RIL-018）：显式携带，不做"反推"。全部幂等——目标不存在
/// 视为已撤销（ENOENT/EEXIST 容忍）；DNS 撤销还原先前内容而非删除。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InverseChange {
    /// 移除本实例添加的路由（幂等：路由不存在视为已撤销）
    RemoveRoute {
        /// 目的网段（CIDR）
        destination: String,
        /// 接口
        interface: String,
    },
    /// 还原先前 DNS 配置内容（**还原而非删除**；None = 启用前无自定义
    /// 配置，还原系统默认行为）
    RestoreDns {
        /// 先前内容（启用前快照）
        previous_content: Option<String>,
    },
    /// 删除本实例添加的防火墙规则（幂等：规则不存在视为已撤销）
    DeleteFirewallRule {
        /// 规则描述（执行方按其定位规则）
        rule: String,
    },
    /// 移除本实例添加的策略路由规则（fwmark → 表）
    RemoveFwmarkRule {
        /// 防火墙标记
        mark: u32,
        /// 策略路由表
        table: u32,
    },
    /// 恢复接口先前状态（本实例拉起的接口恢复 down；先前已 up 的接口
    /// 不在此列——那类登记为 PreExisting）
    RestoreLinkState {
        /// 接口名
        interface: String,
    },
}

/// 副作用日志条目（RIL-018）：单调序号 + 系统面 + 所有权 + 人读描述 +
/// 可选撤销动作（`PreExisting` 恒无撤销动作）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEntry {
    /// 日志内单调递增序号
    pub id: u64,
    /// 系统面
    pub area: SystemArea,
    /// 所有权
    pub ownership: Ownership,
    /// 所有者标识（Owned 条目为实例标识；PreExisting 条目为空串）
    pub owner: String,
    /// 人读描述（如 `route 10.7.0.0/24 dev rillane0`）
    pub description: String,
    /// 撤销动作（仅 Owned 条目携带；PreExisting 恒 None）
    pub inverse: Option<InverseChange>,
}

/// 副作用契约错误（RIL-018）：文案可演进，`code()` 恒定。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SideEffectError {
    /// 试图撤销非本实例所有（他人 Owned 或 PreExisting）的条目
    #[error("{CODE_SIDE_EFFECT_FOREIGN}: 条目 {id} 不属于当前实例（owner: {owner:?}），拒绝撤销")]
    ForeignEntry {
        /// 条目序号
        id: u64,
        /// 条目实际 owner（PreExisting 为空串）
        owner: String,
    },
    /// 日志中不存在该条目
    #[error("{CODE_SIDE_EFFECT_UNKNOWN}: 条目 {id} 不在变更日志中")]
    UnknownEntry {
        /// 条目序号
        id: u64,
    },
}

impl SideEffectError {
    /// 稳定原因码（机器口径）
    pub fn code(&self) -> &'static str {
        match self {
            SideEffectError::ForeignEntry { .. } => CODE_SIDE_EFFECT_FOREIGN,
            SideEffectError::UnknownEntry { .. } => CODE_SIDE_EFFECT_UNKNOWN,
        }
    }
}

/// 系统副作用变更日志（RIL-018）：apply 成功一步、记一步；失败步骤
/// 从不入日志。撤销计划 = 本实例 Owned 条目逆序——任一步失败时回放
/// 该计划即「只撤销本实例修改」；PreExisting 与他人条目从不出现。
#[derive(Debug, Clone, Default)]
pub struct SideEffectJournal {
    entries: Vec<ChangeEntry>,
    next_id: u64,
}

impl SideEffectJournal {
    /// 空日志
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记启动前已存在的系统配置（审计足迹，永不撤销）
    pub fn record_pre_existing(&mut self, area: SystemArea, description: impl Into<String>) -> u64 {
        let id = self.take_id();
        self.entries.push(ChangeEntry {
            id,
            area,
            ownership: Ownership::PreExisting,
            owner: String::new(),
            description: description.into(),
            inverse: None,
        });
        id
    }

    /// 登记本实例已成功应用的变更（apply 成功后调用——失败步骤不入日志）
    pub fn record_owned(
        &mut self,
        area: SystemArea,
        owner: impl Into<String>,
        description: impl Into<String>,
        inverse: InverseChange,
    ) -> u64 {
        let id = self.take_id();
        self.entries.push(ChangeEntry {
            id,
            area,
            ownership: Ownership::Owned,
            owner: owner.into(),
            description: description.into(),
            inverse: Some(inverse),
        });
        id
    }

    /// 全部条目（含 PreExisting——审计可见）
    pub fn entries(&self) -> &[ChangeEntry] {
        &self.entries
    }

    /// 条目数
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 日志是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 按序号查找条目
    pub fn get(&self, id: u64) -> Option<&ChangeEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// 撤销计划：`owner` 实例的 Owned 条目**逆序**（后进先撤销——依赖
    /// 顺序安全，如先删策略规则再删其指向的表路由）。PreExisting 与
    /// 他人条目从不出现（验收「已有系统配置不被误删」）。
    pub fn rollback_plan(&self, owner: &str) -> Vec<InverseChange> {
        self.entries
            .iter()
            .rev()
            .filter(|entry| entry.ownership == Ownership::Owned && entry.owner == owner)
            .filter_map(|entry| entry.inverse.clone())
            .collect()
    }

    /// 单条撤销动作（幂等执行语义由执行方落实）：仅条目所有者本人
    /// 可撤销；PreExisting 或他人条目返回 [`SideEffectError::ForeignEntry`]。
    pub fn undo_entry(&self, id: u64, owner: &str) -> Result<InverseChange, SideEffectError> {
        let entry = self.get(id).ok_or(SideEffectError::UnknownEntry { id })?;
        if entry.ownership != Ownership::Owned || entry.owner != owner {
            return Err(SideEffectError::ForeignEntry {
                id,
                owner: entry.owner.clone(),
            });
        }
        entry
            .inverse
            .clone()
            .ok_or(SideEffectError::UnknownEntry { id })
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_route(destination: &str) -> InverseChange {
        InverseChange::RemoveRoute {
            destination: destination.to_string(),
            interface: "rillane0".to_string(),
        }
    }

    #[test]
    fn rollback_plan_contains_only_owned_reversed() {
        let mut journal = SideEffectJournal::new();
        journal.record_pre_existing(SystemArea::Route, "default via 192.168.1.1 dev eth0");
        journal.record_pre_existing(SystemArea::Dns, "resolv.conf (pre-existing)");
        journal.record_owned(
            SystemArea::Route,
            "instance-a",
            "route 10.7.0.0/24 dev rillane0",
            owned_route("10.7.0.0/24"),
        );
        journal.record_owned(
            SystemArea::Dns,
            "instance-a",
            "resolv.conf rewritten",
            InverseChange::RestoreDns {
                previous_content: Some("nameserver 192.168.1.1\n".to_string()),
            },
        );
        journal.record_owned(
            SystemArea::Firewall,
            "instance-a",
            "fwmark rule 0x1 table 518",
            InverseChange::RemoveFwmarkRule {
                mark: 1,
                table: 518,
            },
        );

        let plan = journal.rollback_plan("instance-a");
        assert_eq!(
            plan,
            vec![
                InverseChange::RemoveFwmarkRule {
                    mark: 1,
                    table: 518
                },
                InverseChange::RestoreDns {
                    previous_content: Some("nameserver 192.168.1.1\n".to_string())
                },
                owned_route("10.7.0.0/24"),
            ],
            "撤销计划 = Owned 逆序，PreExisting 不出现"
        );

        // 日志条目序号单调，PreExisting 无撤销动作
        let ids: Vec<u64> = journal.entries().iter().map(|e| e.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "序号单调");
        for entry in journal.entries() {
            if entry.ownership == Ownership::PreExisting {
                assert!(entry.inverse.is_none(), "PreExisting 恒无撤销动作");
            }
        }
    }

    #[test]
    fn pre_existing_never_undone() {
        let mut journal = SideEffectJournal::new();
        let id = journal.record_pre_existing(SystemArea::Dns, "resolv.conf (pre-existing)");

        let err = journal
            .undo_entry(id, "instance-a")
            .expect_err("PreExisting 拒绝撤销");
        assert_eq!(err.code(), CODE_SIDE_EFFECT_FOREIGN);
        match err {
            SideEffectError::ForeignEntry { owner, .. } => {
                assert_eq!(owner, "", "PreExisting owner 为空串");
            }
            other => panic!("应为 ForeignEntry，实际 {other:?}"),
        }
        assert!(
            journal.rollback_plan("instance-a").is_empty(),
            "撤销计划不包含 PreExisting"
        );
    }

    #[test]
    fn rollback_scoped_to_owner() {
        let mut journal = SideEffectJournal::new();
        journal.record_owned(
            SystemArea::Route,
            "instance-a",
            "route 10.7.0.1/24",
            owned_route("10.7.0.1/24"),
        );
        let b_id = journal.record_owned(
            SystemArea::Firewall,
            "instance-b",
            "fwmark rule 0x2 table 519",
            InverseChange::RemoveFwmarkRule {
                mark: 2,
                table: 519,
            },
        );

        // instance-a 的撤销计划不含 instance-b 的条目（验收：只撤销本实例修改）
        let plan = journal.rollback_plan("instance-a");
        assert_eq!(plan, vec![owned_route("10.7.0.1/24")]);

        // 越权撤销他人条目 → 稳定码拒绝
        let err = journal.undo_entry(b_id, "instance-a").unwrap_err();
        assert_eq!(err.code(), CODE_SIDE_EFFECT_FOREIGN);

        // 所有者本人可撤销
        let inverse = journal.undo_entry(b_id, "instance-b").unwrap();
        assert_eq!(
            inverse,
            InverseChange::RemoveFwmarkRule {
                mark: 2,
                table: 519
            }
        );

        // 未知条目 → 稳定码
        let err = journal.undo_entry(999, "instance-a").unwrap_err();
        assert_eq!(err.code(), CODE_SIDE_EFFECT_UNKNOWN);
    }

    #[test]
    fn failed_step_rolls_back_only_applied() {
        // 模拟 apply 序列：step1 成功、step2 成功、step3 失败（从未入日志）
        let mut journal = SideEffectJournal::new();
        journal.record_pre_existing(SystemArea::Route, "default via 192.168.1.1 dev eth0");
        let _step1 = journal.record_owned(
            SystemArea::Route,
            "instance-a",
            "route 10.7.0.0/24 dev rillane0",
            owned_route("10.7.0.0/24"),
        );
        let _step2 = journal.record_owned(
            SystemArea::Firewall,
            "instance-a",
            "fwmark rule 0x1 table 518",
            InverseChange::RemoveFwmarkRule {
                mark: 1,
                table: 518,
            },
        );
        // step3 失败：不调用 record_owned——日志中无该步骤
        assert_eq!(journal.len(), 3, "失败步骤不入日志");

        // 失败后的回滚计划：只含已成功的本实例条目，逆序
        let plan = journal.rollback_plan("instance-a");
        assert_eq!(
            plan,
            vec![
                InverseChange::RemoveFwmarkRule {
                    mark: 1,
                    table: 518
                },
                owned_route("10.7.0.0/24"),
            ],
            "任一步失败只撤销本实例已应用条目"
        );
        assert!(
            !plan
                .iter()
                .any(|inverse| matches!(inverse, InverseChange::RestoreLinkState { .. })),
            "未执行步骤的撤销动作不存在"
        );
    }

    #[test]
    fn dns_undo_restores_not_deletes() {
        let mut journal = SideEffectJournal::new();
        journal.record_owned(
            SystemArea::Dns,
            "instance-a",
            "resolv.conf rewritten",
            InverseChange::RestoreDns {
                previous_content: Some("nameserver 192.168.1.1\n".to_string()),
            },
        );
        // 启用前无自定义 DNS：还原为系统默认行为（None），而非删除文件
        journal.record_owned(
            SystemArea::Dns,
            "instance-a",
            "resolv.conf rewritten (was system default)",
            InverseChange::RestoreDns {
                previous_content: None,
            },
        );

        let plan = journal.rollback_plan("instance-a");
        assert_eq!(plan.len(), 2);
        // 撤销计划逆序：后记录的（previous_content: None）先撤销
        assert!(matches!(
            &plan[0],
            InverseChange::RestoreDns {
                previous_content: None
            }
        ));
        assert!(matches!(
            &plan[1],
            InverseChange::RestoreDns {
                previous_content: Some(_)
            }
        ));
    }

    #[test]
    fn area_strings_are_stable() {
        assert_eq!(SystemArea::Route.as_str(), "route");
        assert_eq!(SystemArea::Dns.as_str(), "dns");
        assert_eq!(SystemArea::Firewall.as_str(), "firewall");
    }
}
