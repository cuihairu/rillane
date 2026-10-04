//! 插件 ABI 常量与 wire 类型（plugin-loader.md §1.2/§1.3）。

use std::collections::BTreeMap;

/// 线性内存导出名（宿主读写参数/结果区的唯一面）
pub const EXPORT_MEMORY: &str = "memory";
/// bump 分配导出：`alloc(size) -> ptr`（每次调用前分配，生命周期单次调用）
pub const EXPORT_ALLOC: &str = "alloc";
/// 插件名导出：`plugin_name() -> ptr`（NUL 结尾 UTF-8，载入时读一次）
pub const EXPORT_PLUGIN_NAME: &str = "plugin_name";
/// 首块需求声明导出：`wants_payload() -> 0|1`（缺席视为 0）
pub const EXPORT_WANTS_PAYLOAD: &str = "wants_payload";
/// 流裁决入口：`on_flow(ctx_ptr, ctx_len, out_ptr, out_cap) -> i32`（≥0 写出长度）
pub const EXPORT_ON_FLOW: &str = "on_flow";

/// 首块探测上限（字节；§1.3/§2.2——单次 read，内核按到达即返）
pub const FIRST_CHUNK_CAP: usize = 4096;
/// 决策 JSON 输出缓冲（字节；宿主侧上界钳制，§3 内存行）
pub const DECISION_OUT_CAP: u32 = 4096;
/// plugin_name 读取上限（防裸奔模块无界读，§7 R-name）
pub const PLUGIN_NAME_CAP: usize = 256;

/// 宿主 → 插件上下文（§1.3 JSON over 线性内存；`now_ms` 宿主注入——
/// wasm32-unknown-unknown 无时钟，§0 载具裁决）
#[derive(Debug, serde::Serialize)]
pub struct FlowContextJson<'a> {
    pub flow_id: String,
    pub host: &'a str,
    pub port: u16,
    pub proto: &'static str,
    pub now_ms: i64,
    pub annotations: &'a BTreeMap<String, String>,
    /// base64；仅 `wants_payload=1` 且探测到 ≥0 字节时携带
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_chunk: Option<String>,
}

/// 插件 → 宿主决策（§1.3）：deny → 适配器 bail（E8 既有语义）；
/// set/remove_annotations 写 `metadata.annotations`（§1.4 契约同款）。
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PluginDecision {
    pub action: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub set_annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub remove_annotations: Vec<String>,
}

impl PluginDecision {
    pub fn is_deny(&self) -> bool {
        self.action == "deny"
    }
}
