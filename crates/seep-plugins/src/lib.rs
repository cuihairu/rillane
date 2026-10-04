//! P3-2 插件动态加载：WASM `FlowMiddleware` 载入器（wasmtime）。
//!
//! 设计定稿：[docs/design/plugin-loader.md](../../../../docs/design/plugin-loader.md)
//! ——载具裁决 §1.1（WASM-only，动态库直载归 V2）、ABI §1.2/§1.3（JSON over
//! 线性内存，宿主注入 `now_ms`）、宿主侧 §2（载入器/首块回放/配置面）、隔离
//! §3（fuel 指令预算 + trap 收敛）、测试 §4（内联 WAT 单测与示例产物同 ABI 面）。

mod abi;
mod loader;
mod plugin;
mod replay;

pub use abi::{FlowContextJson, PluginDecision, DECISION_OUT_CAP, FIRST_CHUNK_CAP};
pub use loader::{load_plugin, load_plugin_from_bytes};
pub use plugin::{PluginStats, PluginStatsSnapshot, WasmPluginMiddleware};
pub use replay::ReplayIo;

/// 每调用 fuel 指令预算缺省值（plugin-loader.md §2.3 配置块）
pub const DEFAULT_PLUGIN_FUEL: u64 = 100_000_000;

/// 载入选项（plugin-loader.md §2.1）：fuel 预算按调用计（每调用重置，§3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginLoadOptions {
    pub fuel: u64,
}

impl Default for PluginLoadOptions {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_PLUGIN_FUEL,
        }
    }
}

#[cfg(test)]
mod tests {
    use seep_core::{Flow, FlowId, FlowMiddleware, FlowTarget, TargetProto};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    use super::*;

    // ---- 内联 WAT 脚手架（plugin-loader.md §4.1：零外部文件，与示例插件同 ABI 面）----

    const NOOP_DECISION: &str = r#"{"action":"allow","note":"ok","set_annotations":{"plugin.noop.seen":"1"},"remove_annotations":["drop.me"]}"#;
    const DENY_DECISION: &str = r#"{"action":"deny","note":"关键词命中"}"#;

    /// 生成完整插件模块（bump alloc + 名字/首块声明 + on_flow）。
    /// `decision` 提供时 data 段落位 64 并生成标准 on_flow（越界钳制 + memory.copy 回写）；
    /// `custom_on_flow` 提供时覆盖标准体（trap/fuel 用例走自定义，data 段仍按 decision 落位）。
    fn plugin_wat(
        name: &str,
        wants_payload: bool,
        decision: Option<&str>,
        custom_on_flow: Option<&str>,
    ) -> String {
        let escaped = decision
            .unwrap_or("")
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let data_seg = if decision.is_some() {
            format!(r#"        (data (i32.const 64) "{escaped}")"#)
        } else {
            String::new()
        };
        let std_on_flow = format!(
            r#"(func (export "on_flow") (param i32 i32 i32 i32) (result i32)
            (if (i32.lt_u (local.get 3) (i32.const {len})) (then (return (i32.const -1))))
            (memory.copy (local.get 2) (i32.const 64) (i32.const {len}))
            (i32.const {len}))"#,
            len = decision.unwrap_or("").len()
        );
        let on_flow_body = custom_on_flow.unwrap_or(&std_on_flow);
        format!(
            r#"(module
        (memory (export "memory") 1)
        (global $heap (mut i32) (i32.const 1024))
        (data (i32.const 0) "{name}\00")
{data_seg}
        (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $heap))
            (global.set $heap (i32.add (local.get $p) (i32.add (local.get $size) (i32.const 7))))
            (local.get $p))
        (func (export "plugin_name") (result i32) (i32.const 0))
        (func (export "wants_payload") (result i32) (i32.const {}))
        {on_flow_body})"#,
            u32::from(wants_payload)
        )
    }

    /// 首调 trap、次调正常的条件 trap 体（Store 未毒化断言的载体，§4.1）。
    /// 插件全局 `$calls` 在 trap 前已自增——若 Store 被毒化/重置则次调再 trap。
    fn counting_trap_on_flow(len: usize) -> String {
        format!(
            r#"(global $calls (mut i32) (i32.const 0))
        (func (export "on_flow") (param i32 i32 i32 i32) (result i32)
            (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
            (if (i32.eq (global.get $calls) (i32.const 1)) (then (unreachable)))
            (if (i32.lt_u (local.get 3) (i32.const {len})) (then (return (i32.const -1))))
            (memory.copy (local.get 2) (i32.const 64) (i32.const {len}))
            (i32.const {len}))"#,
            len = len
        )
    }

    const SPIN_ON_FLOW: &str = r#"(func (export "on_flow") (param i32 i32 i32 i32) (result i32)
        (loop $spin (br $spin))
        (unreachable))"#;

    async fn make_flow(payload: &[u8]) -> (Flow, tokio::io::DuplexStream) {
        let (mut test_side, flow_io) = tokio::io::duplex(4096);
        test_side.write_all(payload).await.unwrap();
        let mut metadata = seep_core::FlowMetadata::default();
        metadata
            .annotations
            .insert("drop.me".to_string(), "x".to_string());
        (
            Flow {
                id: FlowId::default(),
                target: FlowTarget {
                    host: "example.com".to_string(),
                    port: 443,
                    proto: TargetProto::Tcp,
                },
                io: Box::new(flow_io),
                metadata,
            },
            test_side,
        )
    }

    async fn read_exact<T: AsyncRead + Unpin + ?Sized>(io: &mut T, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        io.read_exact(&mut buf).await.unwrap();
        buf
    }

    // ---- §4.1 用例 ----

    #[tokio::test]
    async fn noop_plugin_allows_and_patches_annotations() {
        let mw = load_plugin_from_bytes(
            plugin_wat("noop-test", false, Some(NOOP_DECISION), None).as_bytes(),
            PluginLoadOptions::default(),
        )
        .unwrap();
        assert_eq!(mw.name(), "noop-test");
        let (flow, mut test_side) = make_flow(b"hello").await;
        let flow = mw.handle(flow).await.unwrap();
        // §1.3 注解写面：set/remove 往返
        assert_eq!(
            flow.metadata.annotations.get("plugin.noop.seen").unwrap(),
            "1"
        );
        assert!(!flow.metadata.annotations.contains_key("drop.me"));
        // 无首块声明（wants_payload=0）→ io 原样透传
        let mut io = flow.io;
        let mut buf = vec![0u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");
        // 决策 JSON 是静态 data 段回写——再读一块应从对端透传（不重复回放）
        test_side.write_all(b"more").await.unwrap();
        assert_eq!(read_exact(&mut io, 4).await, b"more");
    }

    #[tokio::test]
    async fn deny_decision_bails_flow() {
        let mw = load_plugin_from_bytes(
            plugin_wat("deny-test", false, Some(DENY_DECISION), None).as_bytes(),
            PluginLoadOptions::default(),
        )
        .unwrap();
        let (flow, _test_side) = make_flow(b"payload").await;
        let err = mw.handle(flow).await.unwrap_err();
        assert!(err.to_string().contains("deny-test"), "{err:#}");
        assert!(err.to_string().contains("关键词命中"), "{err:#}");
        let stats = mw.stats();
        assert_eq!(stats.denied, 1);
        assert_eq!(stats.calls, 1);
    }

    /// §4.1 核心断言：trap 收敛于该次调用 + Store 未毒化（次调用同实例仍成功）。
    #[tokio::test]
    async fn trap_is_contained_and_store_survives() {
        let wat = plugin_wat(
            "trap-test",
            false,
            Some(NOOP_DECISION),
            Some(&counting_trap_on_flow(NOOP_DECISION.len())),
        );
        let mw = load_plugin_from_bytes(wat.as_bytes(), PluginLoadOptions::default()).unwrap();
        let (flow, _test_side) = make_flow(b"first").await;
        let err = mw.handle(flow).await.unwrap_err();
        assert!(
            err.to_string().contains("trap-test") || err.to_string().contains("trap"),
            "{err:#}"
        );
        let stats = mw.stats();
        assert_eq!(stats.traps, 1, "trap 计 1");
        // 次调：若 Store 被毒化/实例重置，$calls 归零 → 再 trap 而非 Ok
        let (flow, test_side) = make_flow(b"second").await;
        let flow = mw.handle(flow).await.expect("trap 后 Store 应仍可用");
        assert_eq!(
            flow.metadata.annotations.get("plugin.noop.seen").unwrap(),
            "1",
            "trap 后决策面仍生效"
        );
        let mut io = flow.io;
        let mut buf = vec![0u8; 6];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"second");
        drop(io);
        let stats = mw.stats();
        assert_eq!(stats.traps, 1, "次调不再计 trap");
        assert_eq!(stats.calls, 2);
        drop(test_side);
    }

    /// §4.1：死循环 → fuel 耗尽 Err（隔离面 §3 第二行）。
    #[tokio::test]
    async fn infinite_loop_hits_fuel_budget() {
        let wat = plugin_wat("spin-test", false, None, Some(SPIN_ON_FLOW));
        let mw =
            load_plugin_from_bytes(wat.as_bytes(), PluginLoadOptions { fuel: 10_000 }).unwrap();
        let (flow, _test_side) = make_flow(b"x").await;
        let err = mw.handle(flow).await.unwrap_err();
        assert!(err.to_string().contains("fuel"), "{err:#}");
        let stats = mw.stats();
        assert_eq!(stats.fuel_exhausted, 1);
    }

    /// §4.1/§2.2：wants_payload=1 → 首块探测 + allow 回放 + 后续透传。
    #[tokio::test]
    async fn first_chunk_peek_replays_on_allow() {
        let mw = load_plugin_from_bytes(
            plugin_wat("peek-allow", true, Some(NOOP_DECISION), None).as_bytes(),
            PluginLoadOptions::default(),
        )
        .unwrap();
        let (flow, mut test_side) = make_flow(b"PEEKDATA-rest").await;
        let flow = mw.handle(flow).await.unwrap();
        assert_eq!(
            flow.metadata.annotations.get("plugin.noop.seen").unwrap(),
            "1",
            "探测后决策面生效"
        );
        let mut io = flow.io;
        // 探测字节完好回放（§2.2）
        assert_eq!(read_exact(&mut io, 13).await, b"PEEKDATA-rest");
        // 回放尽后透传对端
        test_side.write_all(b"live").await.unwrap();
        assert_eq!(read_exact(&mut io, 4).await, b"live");
    }

    /// §4.1/§2.2：wants_payload=1 + deny → Err（探测字节随流丢弃）。
    #[tokio::test]
    async fn first_chunk_deny_bails() {
        let mw = load_plugin_from_bytes(
            plugin_wat("peek-deny", true, Some(DENY_DECISION), None).as_bytes(),
            PluginLoadOptions::default(),
        )
        .unwrap();
        let (flow, _test_side) = make_flow(b"evil").await;
        assert!(mw.handle(flow).await.is_err());
        assert_eq!(mw.stats().denied, 1);
    }

    /// §4.1 负路径：坏 magic。
    #[test]
    fn loader_rejects_bad_magic() {
        let err =
            load_plugin_from_bytes(b"not-wasm-at-all", PluginLoadOptions::default()).unwrap_err();
        assert!(err.to_string().contains("编译失败"), "{err:#}");
    }

    /// §4.1 负路径：缺必备导出（ABI §1.2）。
    #[test]
    fn loader_rejects_missing_exports() {
        let wat = r#"(module (memory (export "memory") 1))"#;
        let err = load_plugin_from_bytes(wat.as_bytes(), PluginLoadOptions::default()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("plugin_name") || msg.contains("alloc") || msg.contains("on_flow"),
            "{msg}"
        );
    }

    /// 决策缓冲上界（§3 内存行）：插件谎报写入长度 > out_cap → 宿主侧 Err。
    #[tokio::test]
    async fn lying_decision_length_bails() {
        let liar = r#"(func (export "on_flow") (param i32 i32 i32 i32) (result i32)
            (i32.const 99999))"#;
        let mw = load_plugin_from_bytes(
            plugin_wat("cap-test", false, Some(NOOP_DECISION), Some(liar)).as_bytes(),
            PluginLoadOptions::default(),
        )
        .unwrap();
        let (flow, _test_side) = make_flow(b"x").await;
        let err = mw.handle(flow).await.unwrap_err();
        assert!(err.to_string().contains("越界"), "{err:#}");
    }
}
