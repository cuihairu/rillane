//! `MiddlewareChain` 管线语义（obfuscation-middleware.md §7.1：空链零调用 /
//! 声明序执行 / Err 中止 E8；§2.5 空链 = 关闭态）。

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use seep_core::{
    Flow, FlowId, FlowMetadata, FlowMiddleware, FlowTarget, MiddlewareChain, TargetProto,
};

/// 记录型 mock：执行序写共享向量；`fail` 注入 Err（E8 路径）；
/// 成功时追加自己的注解（后继 middleware 可见 = Flow 线程化证据）。
struct RecordingMiddleware {
    name: &'static str,
    calls: Arc<Mutex<Vec<&'static str>>>,
    fail: bool,
}

#[async_trait]
impl FlowMiddleware for RecordingMiddleware {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn handle(&self, mut flow: Flow) -> Result<Flow> {
        self.calls.lock().expect("calls lock").push(self.name);
        if self.fail {
            return Err(anyhow!("middleware {} 失败（E8 注入）", self.name));
        }
        flow.metadata
            .annotations
            .insert(format!("mw.{name}", name = self.name), "1".to_string());
        Ok(flow)
    }
}

fn dummy_flow() -> Flow {
    Flow {
        id: FlowId::new(),
        target: FlowTarget {
            host: "example.com".to_string(),
            port: 443,
            proto: TargetProto::Tcp,
        },
        io: Box::new(tokio::io::duplex(64).1),
        metadata: FlowMetadata::default(),
    }
}

/// §2.5/§7.1：空链（Default = 关闭态）run 直接返回——零调用断言（不在链内
/// 的 mock 计数恒 0）、流原样穿透（id 不变）。
#[tokio::test]
async fn empty_chain_run_is_noop() {
    let chain = MiddlewareChain::default();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);

    let src = dummy_flow();
    let src_id = src.id;
    let flow = chain.run(src).await.expect("空链 run 应成功");
    assert_eq!(flow.id, src_id, "流应原样穿透");
    assert!(flow.metadata.annotations.is_empty());

    // 零调用断言：链外的旁观 mock 从未被调用
    let calls = Arc::new(Mutex::new(Vec::new()));
    let _bystander = RecordingMiddleware {
        name: "bystander",
        calls: calls.clone(),
        fail: false,
    };
    assert!(calls.lock().expect("calls lock").is_empty());
}

/// §1.5/§7.1：声明序即执行序；Flow 在 middleware 间线程化传递（先序注解
/// 对后继可见）。
#[tokio::test]
async fn declaration_order_is_execution_order_and_flow_threads_through() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let chain = MiddlewareChain::new(vec![
        Arc::new(RecordingMiddleware {
            name: "a",
            calls: calls.clone(),
            fail: false,
        }),
        Arc::new(RecordingMiddleware {
            name: "b",
            calls: calls.clone(),
            fail: false,
        }),
    ]);
    assert_eq!(chain.len(), 2);

    let flow = chain.run(dummy_flow()).await.expect("链 run 应成功");
    assert_eq!(*calls.lock().expect("calls lock"), vec!["a", "b"]);
    assert!(flow.metadata.annotations.contains_key("mw.a"));
    assert!(flow.metadata.annotations.contains_key("mw.b"));
}

/// §6 E8/§7.1：任一 middleware Err 即中止——错误冒泡（run 返回 Err），
/// 后续 middleware 不执行。
#[tokio::test]
async fn error_aborts_remaining_middlewares() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let chain = MiddlewareChain::new(vec![
        Arc::new(RecordingMiddleware {
            name: "boom",
            calls: calls.clone(),
            fail: true,
        }),
        Arc::new(RecordingMiddleware {
            name: "after",
            calls: calls.clone(),
            fail: false,
        }),
    ]);

    let err = chain
        .run(dummy_flow())
        .await
        .expect_err("首个 middleware Err 应冒泡（E8）");
    assert!(err.to_string().contains("boom"), "{err}");
    assert_eq!(
        *calls.lock().expect("calls lock"),
        vec!["boom"],
        "中止后不执行后续"
    );
}

/// P1-4 §5：run 计入进程级调用计数（`middleware_invocations`，键 = name、
/// 调用即计数——E8 注入失败的调用同样计入；空链 run 不产生条目）。
#[tokio::test]
async fn invocations_counted_per_name() {
    fn get(snap: &[(&'static str, u64)], name: &str) -> u64 {
        snap.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
    let before = seep_core::middleware_invocations();

    let calls_a = Arc::new(Mutex::new(Vec::new()));
    let calls_b = Arc::new(Mutex::new(Vec::new()));
    let chain = MiddlewareChain::new(vec![
        Arc::new(RecordingMiddleware {
            name: "inva",
            calls: calls_a.clone(),
            fail: false,
        }),
        Arc::new(RecordingMiddleware {
            name: "invb",
            calls: calls_b.clone(),
            fail: true,
        }),
    ]);
    // 两轮：invb 每轮 Err 冒泡，但"调用"本身两轮均已发生
    let _ = chain.run(dummy_flow()).await;
    let _ = chain.run(dummy_flow()).await;
    let after = seep_core::middleware_invocations();
    assert_eq!(
        get(&after, "inva"),
        get(&before, "inva") + 2,
        "两轮各计一次"
    );
    assert_eq!(
        get(&after, "invb"),
        get(&before, "invb") + 2,
        "Err 的调用同样计入（调用即计数）"
    );
}
