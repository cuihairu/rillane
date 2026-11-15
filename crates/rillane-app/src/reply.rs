//! 答复与错误语义（RIL-065）：控制面版本化信封的解码契约。缺席
//! （found:false）与错误信封（error.code/context）在这里分立——表面
//! （CLI/UI/MCP）据稳定码映射行为（如 CLI 缺席退出码 2），语义不随
//! 执行器漂移。信封形状冻结：`{"schema_version":1, ...}`。

use serde_json::Value;

/// 显式缺席答复（found:false 信封的 absence 对象投影——无记录 ≠
/// 未发包，note 固定说明原样带出）
#[derive(Debug, Clone, PartialEq)]
pub struct AbsenceAnswer {
    pub code: String,
    pub note: String,
    pub collector: Option<Value>,
}

/// 成功答复（2xx）：JSON 信封（schema_version 校验）或纯文本
/// 正文（SVG 导出面）。
#[derive(Debug, Clone, PartialEq)]
pub struct AppReply {
    pub status: u16,
    /// 信封版本（文本正文为 None——SVG 无信封）
    pub schema_version: Option<u32>,
    pub json: Option<Value>,
    pub text: Option<String>,
}

impl AppReply {
    /// 信封 JSON（文本正文面返回 None）
    pub fn json(&self) -> Option<&Value> {
        self.json.as_ref()
    }

    /// found 位（found:false 才算缺席——其余形态不算）
    pub fn found(&self) -> Option<bool> {
        self.json.as_ref()?.get("found").and_then(|f| f.as_bool())
    }

    /// 显式缺席投影（须 found:false 且带 absence 对象）
    pub fn absence(&self) -> Option<AbsenceAnswer> {
        if self.found() != Some(false) {
            return None;
        }
        let absence = self.json.as_ref()?.get("absence")?;
        Some(AbsenceAnswer {
            code: absence
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("unknown")
                .to_string(),
            note: absence
                .get("note")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
            collector: absence.get("collector").cloned(),
        })
    }
}

/// 错误（传输失败 / 非 2xx / 信封外形态）。`status: None` = 传输层
/// 失败（连接不上等——未到达控制面，无状态码）；`code` 优先取信封
/// 稳定码，正文非信封时给占位码不 panic（正文摘要进 context）。
#[derive(Debug, Clone, PartialEq)]
pub struct AppError {
    pub status: Option<u16>,
    pub code: String,
    pub context: String,
}

impl AppError {
    /// 客户端侧参数拒绝（构造操作时即拒绝——非法值不发请求）
    pub fn param(code: &str, context: &str) -> Self {
        Self {
            status: None,
            code: code.to_string(),
            context: context.to_string(),
        }
    }

    /// 传输层失败（未到达控制面）
    pub fn transport(context: String) -> Self {
        Self {
            status: None,
            code: "control.unreachable".to_string(),
            context,
        }
    }

    /// 从非 2xx 响应解码：error 信封稳定码优先，absence 信封（404 +
    /// found:false——缺席也是信封不是错误）次之，非信封正文给占位码
    pub fn from_response(status: u16, body: &str) -> Self {
        let parsed: Option<Value> = serde_json::from_str(body).ok();
        let error = parsed.as_ref().and_then(|v| v.get("error"));
        let absence = parsed.as_ref().and_then(|v| v.get("absence"));
        let code = error
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str())
            .or_else(|| absence.and_then(|a| a.get("code")).and_then(|c| c.as_str()))
            .map(String::from)
            .unwrap_or_else(|| format!("control.http.{status}"));
        let context = error
            .and_then(|e| e.get("context"))
            .and_then(|c| c.as_str())
            .or_else(|| {
                error
                    .and_then(|e| e.get("message"))
                    .and_then(|c| c.as_str())
            })
            .or_else(|| absence.and_then(|a| a.get("note")).and_then(|c| c.as_str()))
            .map(String::from)
            .unwrap_or_else(|| truncate_body(body));
        Self {
            status: Some(status),
            code,
            context,
        }
    }
}

/// 正文摘要（错误 context 兜底——有界，不整段携带）
fn truncate_body(body: &str) -> String {
    let trimmed = body.trim();
    let mut out: String = trimmed.chars().take(200).collect();
    if trimmed.chars().count() > 200 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absence_requires_found_false_and_absence_object() {
        let absent = AppReply {
            status: 200,
            schema_version: Some(1),
            json: Some(json!({
                "schema_version": 1u32,
                "found": false,
                "trace": null,
                "absence": {"code": "collector.flow.evicted", "note": "n", "collector": {"x": 1}},
            })),
            text: None,
        };
        let a = absent.absence().expect("absence projected");
        assert_eq!(a.code, "collector.flow.evicted");
        assert_eq!(a.note, "n");
        assert_eq!(a.collector, Some(json!({"x": 1})));

        // found:true 不算缺席
        let found = AppReply {
            status: 200,
            schema_version: Some(1),
            json: Some(json!({"schema_version": 1u32, "found": true})),
            text: None,
        };
        assert!(found.absence().is_none());
        // found 缺位不算缺席（其余形态不冒充）
        let no_found = AppReply {
            status: 200,
            schema_version: Some(1),
            json: Some(json!({"schema_version": 1u32})),
            text: None,
        };
        assert!(no_found.absence().is_none());
    }

    #[test]
    fn error_decodes_envelope_code_and_context() {
        let err = AppError::from_response(
            404,
            r#"{"schema_version":1,"error":{"code":"collector.flow.expired","context":"ttl"}}"#,
        );
        assert_eq!(err.status, Some(404));
        assert_eq!(err.code, "collector.flow.expired");
        assert_eq!(err.context, "ttl");
    }

    #[test]
    fn error_message_field_feeds_context() {
        // 配置事务信封（RIL-079/RIL-080）{"error":{"code","message"}}：
        // 稳定码照取，message 进 context（daemon 侧消息已脱敏）
        let err = AppError::from_response(
            409,
            r#"{"error":{"code":"apply.base.conflict","message":"现役代际已前进"}}"#,
        );
        assert_eq!(err.status, Some(409));
        assert_eq!(err.code, "apply.base.conflict");
        assert_eq!(err.context, "现役代际已前进");
    }

    #[test]
    fn error_falls_back_for_non_envelope_body() {
        let err = AppError::from_response(500, "<html>oops</html>");
        assert_eq!(err.status, Some(500));
        assert_eq!(err.code, "control.http.500");
        assert!(err.context.contains("oops"));

        // 超长正文有界
        let long = "x".repeat(1_000);
        let err = AppError::from_response(503, &long);
        assert!(err.context.chars().count() <= 201);
    }

    #[test]
    fn absence_shaped_404_decodes_code_and_note() {
        // 探测结果未知：404 + found:false 信封（缺席也是信封——码与说明
        // 不落到占位码）
        let err = AppError::from_response(
            404,
            r#"{"schema_version":1,"found":false,"job":null,"absence":{"code":"probe.job.unknown","note":"no such job"}}"#,
        );
        assert_eq!(err.status, Some(404));
        assert_eq!(err.code, "probe.job.unknown");
        assert_eq!(err.context, "no such job");
    }
}
