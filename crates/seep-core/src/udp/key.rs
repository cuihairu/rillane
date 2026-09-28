//! 粘滞键：进程 > 认证用户 + 五元组 > 五元组（udp-session-table.md §3）。

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// UDP 会话粘滞键。字段整体参与 `Hash`/`Eq`——维度出现即参与区分
/// （"同机两个游戏 = 两个会话"）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UdpSessionKey {
    /// 五元组基线：入站客户端数据报源地址（恒有）
    pub client: SocketAddr,
    /// socks5 认证用户名（无认证为 None；NAT 后多客户端退化场景见设计 O1）
    pub user: Option<String>,
    /// 进程身份（P1 TUN 注入；P0 阶段恒为 None）
    pub process: Option<ProcessIdentity>,
}

impl UdpSessionKey {
    pub fn new(client: SocketAddr) -> Self {
        Self { client, user: None, process: None }
    }

    pub fn with_user(mut self, user: Option<String>) -> Self {
        self.user = user.map(|u| u.to_lowercase());
        self
    }

    pub fn with_process(mut self, process: Option<ProcessIdentity>) -> Self {
        self.process = process;
        self
    }
}

/// 进程身份（P1 TUN 阶段填充；`name` 允许跨 pid 复用会话归并）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
}
