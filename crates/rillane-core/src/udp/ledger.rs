//! `SessionLedger`：FlowSession 的单写入口（udp-session-table.md §6）。
//! UDP 语义包装：包级记账 + O7 退化规则（Failed 会话收到新包即恢复 Active，
//! 因 UDP 链路故障被视为可退化而非终态）。

use crate::udp::metrics::Dir;
use crate::{FailureType, FlowId, FlowSession, RouteDecision, SessionStatus, SessionUsage};
use std::sync::{Mutex, RwLock};

/// 会话台账：包装 [`FlowSession`]，提供锁内短临界区的单写者语义。
pub struct SessionLedger {
    session: RwLock<FlowSession>,
    /// 会话当前绑定的逻辑链（P0-2 接线；None = 直连/未 attach）
    chain_id: Mutex<Option<String>>,
}

impl SessionLedger {
    /// FlowSession::new 会丢弃 target 参数，这里以占位目标构造
    pub fn create(id: FlowId) -> Self {
        let placeholder = crate::FlowTarget {
            host: String::new(),
            port: 0,
            proto: crate::TargetProto::Udp,
        };
        Self {
            session: RwLock::new(FlowSession::new(id, placeholder)),
            chain_id: Mutex::new(None),
        }
    }

    /// 数据包记账；同时执行 O7 恢复（Initializing/Failed/Idle → Active）。
    pub fn on_packet(&self, dir: Dir, bytes: usize) {
        let mut s = self.session.write().unwrap();
        match dir {
            Dir::Up => s.usage.bytes_uploaded += bytes as u64,
            Dir::Down => s.usage.bytes_downloaded += bytes as u64,
        }
        s.usage.packets_count += 1;
        s.last_active = std::time::Instant::now();
        if matches!(
            s.status,
            SessionStatus::Initializing | SessionStatus::Failed | SessionStatus::Idle
        ) {
            s.status = SessionStatus::Active;
        }
    }

    /// 粘滞决策重建时回写路由（沿用 FlowSession 的 route_history 语义）
    pub fn on_route_changed(&self, decision: &RouteDecision) {
        let mut s = self.session.write().unwrap();
        s.update_route(
            decision.all_nodes(),
            decision.reason.clone().unwrap_or_default(),
        );
    }

    /// 记录会话当前所在链（决策变更时由表调用）
    pub fn attach_chain(&self, chain_id: &str) {
        *self.chain_id.lock().unwrap() = Some(chain_id.to_string());
    }

    /// 链路故障：若与本会话相关，记录 Route 失败并返回需吊销映射的失败节点
    /// 列表；无关链路返回 None（表侧据此跳过本会话的映射吊销）。
    pub fn on_link_failure(&self, chain_id: &str, failed_nodes: &[String]) -> Option<Vec<String>> {
        let bound = self.chain_id.lock().unwrap().clone();
        match bound {
            Some(b) if b == chain_id => {
                self.on_error(FailureType::Route);
                Some(failed_nodes.to_vec())
            }
            // 未 attach 链的会话（直连）不在链故障范围内
            _ => None,
        }
    }

    /// 通用错误记账（发送失败/超时分类后调用）
    pub fn on_error(&self, failure_type: FailureType) {
        self.session.write().unwrap().record_failure(failure_type);
    }

    /// 用量读出（表快照 / /flows 渲染用）
    pub fn usage(&self) -> SessionUsage {
        self.session.read().unwrap().usage.clone()
    }

    pub fn status(&self) -> SessionStatus {
        self.session.read().unwrap().status.clone()
    }

    /// 当前路径（快照渲染；FlowSession::current_path 透传）
    pub fn current_path(&self) -> Vec<String> {
        self.session.read().unwrap().current_path.clone()
    }
}
