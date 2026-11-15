//! MCP 服务端范围鉴权（RIL-068，debug-and-mcp.md §5）：授权档与
//! 速率限制的**纯引擎**——stdio 装配面（rillane-mcp）在启动时一次性
//! 构造授权态，请求面没有任何字段能改它（模型声称授权不能升级范围
//! 是结构性保证：GrantedScopes 只来自启动配置）。
//!
//! 契约要点：
//! - 授权只读 [`crate::tools::ToolContract::scope`]（服务端内部口径），
//!   工具注解（hint 字段）永不参与任何授权判断；
//! - 凭证（admin token）留在适配器执行器私有字段——授权面见范围，
//!   不见凭证；拒绝答复只带稳定码与所需档名，不带凭证、不带请求体；
//! - 速率限制是**固定窗口**计数（默认按分钟窗）——超限稳定码
//!   [`RATE_LIMITED_CODE`]，窗口推进即恢复；
//! - 拒绝先于执行：越权/超限的请求不进入任何工具执行（更不到控制面）。

use crate::mcp::JsonRpcError;
use crate::tools::Scope;
use serde_json::json;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// 越权拒绝稳定码（服务端区间 -32001——协议面 -32602/-32022 已被
/// 参数与版本语义占用，授权是另一档）
pub const SCOPE_DENIED_CODE: i32 = -32001;

/// 速率超限稳定码（服务端区间 -32002）
pub const RATE_LIMITED_CODE: i32 = -32002;

/// 越权拒绝答复形：data 只带所需档名（机器口径）——不带凭证、不带
/// 请求体、不带工具参数回显
pub fn scope_denied_error(scope: Scope) -> JsonRpcError {
    JsonRpcError {
        code: SCOPE_DENIED_CODE,
        message: "tool requires a scope not granted to this session".to_string(),
        data: Some(json!({"code": "mcp.scope.denied", "required": scope_name(scope)})),
    }
}

/// 速率超限答复形：data 带窗口秒数（机器口径）
pub fn rate_limited_error(window: Duration) -> JsonRpcError {
    JsonRpcError {
        code: RATE_LIMITED_CODE,
        message: "tool call rate limit exceeded".to_string(),
        data: Some(json!({
            "code": "mcp.rate.limited",
            "window_secs": window.as_secs(),
        })),
    }
}

/// 授权档的线上名（CLI/错误 data 共用此口径）
pub fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::Read => "read",
        Scope::DetailedIdentity => "detailed",
        Scope::Probe => "probe",
        Scope::Write => "write",
    }
}

/// 已授范围集（**只**来自启动配置——请求面没有能改变它的字段）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedScopes {
    inner: HashSet<Scope>,
}

impl GrantedScopes {
    /// 解析逗号分隔档名（`read,detailed,probe`）。未知档名/空串拒绝
    /// （启动期失败——装配面 exit 1，不带病运行）。
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut inner = HashSet::new();
        for part in spec.split(',') {
            let part = part.trim();
            let scope = match part {
                "read" => Scope::Read,
                "detailed" => Scope::DetailedIdentity,
                "probe" => Scope::Probe,
                "write" => Scope::Write,
                other => {
                    return Err(format!(
                        "unknown scope `{other}` (read|detailed|probe|write)"
                    ))
                }
            };
            inner.insert(scope);
        }
        if inner.is_empty() {
            return Err("at least one scope is required".to_string());
        }
        Ok(Self { inner })
    }

    /// 默认授权：只读（最小面——不显式给参就没有越权可能）
    pub fn read_only() -> Self {
        Self {
            inner: HashSet::from([Scope::Read]),
        }
    }

    pub fn grants(&self, scope: Scope) -> bool {
        self.inner.contains(&scope)
    }
}

/// 固定窗口速率限制器（每窗 max_calls 次；窗口边界推进即恢复）。
/// `try_acquire_at` 收注入时钟——测试不睡真实时间。
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_calls: u32,
    window: Duration,
    window_start: Instant,
    used: u32,
}

impl RateLimiter {
    /// `max_calls == 0` = 不限速（显式关闸；其余值至少 1）
    pub fn new(max_calls: u32, window: Duration, now: Instant) -> Self {
        Self {
            max_calls,
            window,
            window_start: now,
            used: 0,
        }
    }

    /// 尝试占一个配额：窗口内超限 → false（并答 [`rate_limited_error`]）；
    /// 窗口过期 → 推进窗口重置计数。
    pub fn try_acquire_at(&mut self, now: Instant) -> bool {
        if self.max_calls == 0 {
            return true;
        }
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= self.max_calls {
            return false;
        }
        self.used += 1;
        true
    }

    pub fn window(&self) -> Duration {
        self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_frozen_names_and_rejects_unknown() {
        let g = GrantedScopes::parse("read,detailed").expect("parse");
        assert!(g.grants(Scope::Read));
        assert!(g.grants(Scope::DetailedIdentity));
        assert!(!g.grants(Scope::Probe));
        assert!(!g.grants(Scope::Write));

        // write 档可授（当前无 write 工具——授了也无面，语义如实）
        let g = GrantedScopes::parse("write").expect("parse");
        assert!(g.grants(Scope::Write));

        assert!(GrantedScopes::parse("telepathy").is_err());
        assert!(GrantedScopes::parse("").is_err());
        assert!(GrantedScopes::parse("  ").is_err());

        // 默认 = 只读（最小面）
        assert!(GrantedScopes::read_only().grants(Scope::Read));
        assert!(!GrantedScopes::read_only().grants(Scope::Probe));
    }

    #[test]
    fn denial_error_carries_scope_name_only() {
        let err = scope_denied_error(Scope::Probe);
        assert_eq!(err.code, SCOPE_DENIED_CODE);
        assert_eq!(err.code, -32001);
        let data = err.data.as_ref().expect("data");
        assert_eq!(data["code"], "mcp.scope.denied");
        assert_eq!(data["required"], "probe");
        // data 形只有 code + required——不带请求参数回显
        assert_eq!(data.as_object().map(|o| o.len()), Some(2));
    }

    #[test]
    fn rate_limiter_is_fixed_window_with_injected_clock() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60), start);
        let at = |secs: u64| start + Duration::from_secs(secs);
        assert!(limiter.try_acquire_at(at(0)));
        assert!(limiter.try_acquire_at(at(1)));
        assert!(limiter.try_acquire_at(at(2)));
        // 窗口内第 4 次 → 超限
        assert!(!limiter.try_acquire_at(at(3)));
        assert_eq!(limiter.window(), Duration::from_secs(60));
        // 窗口推进 → 重置
        assert!(limiter.try_acquire_at(at(61)));
        // 窗口内又能连续 3 次
        assert!(limiter.try_acquire_at(at(62)));
        assert!(limiter.try_acquire_at(at(63)));
        assert!(!limiter.try_acquire_at(at(64)));
    }

    #[test]
    fn unlimited_limiter_never_denies() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(0, Duration::from_secs(60), start);
        for i in 0..10_000u32 {
            assert!(limiter.try_acquire_at(start + Duration::from_millis(i as u64)));
        }
    }

    #[test]
    fn rate_error_carries_window_not_caller_identity() {
        let err = rate_limited_error(Duration::from_secs(60));
        assert_eq!(err.code, RATE_LIMITED_CODE);
        assert_eq!(err.code, -32002);
        let data = err.data.expect("data");
        assert_eq!(data["code"], "mcp.rate.limited");
        assert_eq!(data["window_secs"], 60);
    }
}
