//! 参考执行器（`client-blocking` 特性）：CLI 用的阻塞式 HTTP 执行器。
//! base URL 与 admin token **只进不出**（私有字段、无读取口），公有面
//! 只有 [`BlockingApp::execute`]——URL 拼装、令牌注入、信封解码全部
//! 内聚，表面代码只见操作与答复。异步执行器随 MCP 装配（RIL-067）
//! 另行落地，共用同一 ops/reply 契约。

use crate::ops::{AppOperation, Method};
use crate::reply::{AppError, AppReply};

/// 阻塞式应用服务客户端（单一执行入口——无通用请求面）
pub struct BlockingApp {
    base: String,
    token: Option<String>,
    http: reqwest::blocking::Client,
}

impl BlockingApp {
    /// 构造：base URL 非空校验（空白拒绝——同 CLI 旧口径），token 可选
    pub fn new(base: &str, token: Option<&str>) -> Result<Self, AppError> {
        let trimmed = base.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            return Err(AppError::param("control.base.invalid", "base url is empty"));
        }
        Ok(Self {
            base: trimmed,
            token: token.map(String::from),
            http: reqwest::blocking::Client::new(),
        })
    }

    /// 查询串拼装（干净形态：`?k=v&k2=v2`；无参数则裸路径）
    fn url(&self, req: &crate::ops::OpRequest) -> String {
        let mut url = format!("{}{}", self.base, req.path);
        if !req.query.is_empty() {
            url.push('?');
            let pairs: Vec<String> = req.query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            url.push_str(&pairs.join("&"));
        }
        url
    }

    /// 执行一个操作：2xx → [`AppReply`]；非 2xx → 信封解码的
    /// [`AppError`]；传输失败 → `control.unreachable`。
    pub fn execute(&self, op: AppOperation) -> Result<AppReply, AppError> {
        let req = op.request()?;
        let url = self.url(&req);
        let mut builder = match req.method {
            Method::Get => self.http.get(&url),
            Method::Post => self.http.post(&url),
        };
        if let Some(token) = &self.token {
            builder = builder.header("x-admin-token", token);
        }
        if let Some(body) = &req.body {
            builder = builder.json(body);
        }
        let resp = builder
            .send()
            .map_err(|e| AppError::transport(format!("{}: {e}", op.name())))?;
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| AppError::transport(format!("{}: {e}", op.name())))?;
        if !(200..300).contains(&status) {
            return Err(AppError::from_response(status, &body));
        }
        // JSON 信封优先；非 JSON 正文按文本携带（SVG 导出面）
        let (json, text, schema_version) = match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => (
                Some(v.clone()),
                None,
                v.get("schema_version")
                    .and_then(|s| s.as_u64())
                    .map(|s| s as u32),
            ),
            Err(_) => (None, Some(body), None),
        };
        Ok(AppReply {
            status,
            schema_version,
            json,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::AppOperation;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// 最小 HTTP 应答器（单连接）：记录请求行/头部，回给定状态与正文
    fn one_shot_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Option<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                *seen2.lock().expect("lock") = Some(request);
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[test]
    fn new_rejects_empty_base() {
        assert!(BlockingApp::new("  ", None).is_err());
        assert!(BlockingApp::new("", None).is_err());
        // 尾斜杠归一
        let app = BlockingApp::new("http://127.0.0.1:9/", None).expect("base ok");
        assert_eq!(app.base, "http://127.0.0.1:9");
    }

    #[test]
    fn execute_sends_token_header_and_clean_query() {
        let (base, seen) = one_shot_server(
            "HTTP/1.1 200 OK",
            r#"{"schema_version":1,"found":true,"trace":{}}"#,
        );
        let app = BlockingApp::new(&base, Some("sekrit-token-1")).expect("app");
        let reply = app
            .execute(AppOperation::FlowTrace {
                id: "f-1".to_string(),
            })
            .expect("reply");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.schema_version, Some(1));
        assert_eq!(reply.found(), Some(true));
        let request = seen.lock().expect("lock").clone().expect("request seen");
        assert!(request.starts_with("GET /trace/flow?id=f-1 HTTP/1.1"));
        assert!(request.contains("x-admin-token: sekrit-token-1"));
        // 干净查询形态（无 `?&` 残留）
        assert!(!request.contains("?&"));
    }

    #[test]
    fn execute_maps_non_2xx_to_envelope_error() {
        let (base, _seen) = one_shot_server(
            "HTTP/1.1 404 Not Found",
            r#"{"schema_version":1,"error":{"code":"collector.flow.expired","context":"ttl"}}"#,
        );
        let app = BlockingApp::new(&base, None).expect("app");
        let err = app
            .execute(AppOperation::FlowTrace {
                id: "f-1".to_string(),
            })
            .expect_err("error");
        assert_eq!(err.status, Some(404));
        assert_eq!(err.code, "collector.flow.expired");
    }

    #[test]
    fn execute_carries_post_body_json() {
        let (base, seen) = one_shot_server("HTTP/1.1 200 OK", r#"{"schema_version":1,"job_id":7}"#);
        let app = BlockingApp::new(&base, None).expect("app");
        let reply = app
            .execute(AppOperation::ProbeSubmit(crate::ops::ProbeJobSpec::Dns {
                host: "example.com".to_string(),
            }))
            .expect("reply");
        assert_eq!(
            reply
                .json()
                .and_then(|j| j.get("job_id"))
                .and_then(|v| v.as_u64()),
            Some(7)
        );
        let request = seen.lock().expect("lock").clone().expect("request seen");
        assert!(request.starts_with("POST /probe HTTP/1.1"));
        assert!(request.contains(r#""kind":"dns""#));
        assert!(request.contains(r#""host":"example.com""#));
    }
}
