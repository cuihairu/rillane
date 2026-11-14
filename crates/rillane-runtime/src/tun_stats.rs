//! TUN 统计快照（平台无关面）。
//!
//! 从 tun_ingress.rs 独立出来：控制面指标族 `rillane_tun_*` 恒渲染口径
//! （tun-dataplane.md §2.8——未装配 TUN 时全零，端点不因开关消失）要求
//! 非 Linux 编译单元（windows-gnu 打包面，platform-packaging.md）也能
//! 引用同形状类型渲染零值面。TunIngress 主体仍在 tun_ingress（Linux 门控）。

/// TunIngress 统计（方向语义：received = tun 上行读入；sent = tun 下行写回——
/// 与「代理出站发送」无关，后者归 UDP 序列自身的指标）
#[derive(Debug, Clone, Default)]
pub struct TunIngressStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bypass_dropped: u64,
    pub parse_errors: u64,
    pub unknown_flow: u64,
    pub process_attr_miss: u64,
}
