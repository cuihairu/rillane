//! 应用服务边界（RIL-065，debug-and-mcp.md §5）：CLI/UI/MCP 共用的
//! 窄化诊断与配置调用契约。操作集是**闭合枚举**——每一个调用都有名有
//! 型有界，请求行/路径/参数由 [`ops::AppOperation::request`] 纯函数从
//! 类型化载荷构造，不存在「转发任意方法+路径」的入口（结构性无通用
//! HTTP、无 shell、无任意文件读、无原始管理员面透传——原始配置与订阅
//! URL 是管理员-grade 面，刻意不入本边界；配置变更经 RIL-073+ 提案
//! 面另行进入）。
//!
//! 分层：
//! - [`ops`]：闭合操作集 → [`ops::OpRequest`]（method/path/query/body），
//!   纯函数、零 IO、全量契约测试钉住每一操作的请求形状；
//! - [`reply`]：状态码 + 正文 → [`reply::AppReply`] / [`reply::AppError`]
//!   （版本化信封 + 稳定码解码——缺席/错误语义不随执行器漂移）；
//! - `client`（`client-blocking` 特性）：参考执行器 [`client::BlockingApp`]
//!   ——base URL 与 admin token 只进不出，公有面只有 `execute`。
//!
//! 内核（rillane-core）不依赖本 crate、不依赖任何 MCP SDK——边界是
//! 单向的：表面消费内核契约，内核对面无感知。

pub mod ops;
pub mod reply;

#[cfg(feature = "client-blocking")]
pub mod client;

#[cfg(feature = "client-blocking")]
pub use client::BlockingApp;
pub use ops::AppOperation;
pub use reply::AppError;
