//! 插件适配器（plugin-loader.md §2.1/§3）：`Store` Mutex 串行化 +
//! fuel/trap 双隔离面 + per-plugin 计数。

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use rillane_core::{Flow, FlowMiddleware, TargetProto};
use tokio::io::AsyncReadExt;
use wasmtime::TypedFunc;

use crate::{
    abi::{FlowContextJson, PluginDecision, DECISION_OUT_CAP, FIRST_CHUNK_CAP},
    replay::ReplayIo,
};

/// per-plugin 观测计数（plugin-loader.md §0 计数面；Relaxed——诊断面）
#[derive(Debug, Default)]
pub struct PluginStats {
    pub calls: AtomicU64,
    pub denied: AtomicU64,
    pub traps: AtomicU64,
    pub fuel_exhausted: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PluginStatsSnapshot {
    pub calls: u64,
    pub denied: u64,
    pub traps: u64,
    pub fuel_exhausted: u64,
}

impl PluginStats {
    pub fn snapshot(&self) -> PluginStatsSnapshot {
        PluginStatsSnapshot {
            calls: self.calls.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            traps: self.traps.load(Ordering::Relaxed),
            fuel_exhausted: self.fuel_exhausted.load(Ordering::Relaxed),
        }
    }
}

/// 单实例虚拟机面（plugin-loader.md §2.1）：Store/实例/导出函数打包互斥。
/// `Mutex` 串行化 = 同实例全部流共享插件全局状态（令牌桶语义正确性所在）；
/// 守卫不跨 await（`invoke` 全同步，§9 偏差 4）。
pub struct WasmVm {
    pub store: wasmtime::Store<()>,
    pub alloc_fn: TypedFunc<u32, u32>,
    pub on_flow_fn: TypedFunc<(u32, u32, u32, u32), i32>,
    pub memory: wasmtime::Memory,
}

/// trap/fuel 分类（§3 隔离表）：OutOfFuel 与一般 trap 分记，其余原样冒泡。
/// wasmtime 49 自有 `Error` 类型（非 anyhow re-export）——分类后 `.into()` 过桥。
fn classify_call_err(err: wasmtime::Error, stats: &PluginStats) -> anyhow::Error {
    if err.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::OutOfFuel) {
        stats.fuel_exhausted.fetch_add(1, Ordering::Relaxed);
        return err
            .context("fuel 耗尽（指令预算打满，plugin-loader.md §3；wall-clock 只观测不中止）")
            .into();
    }
    if err.downcast_ref::<wasmtime::Trap>().is_some() {
        stats.traps.fetch_add(1, Ordering::Relaxed);
        return err
            .context("WASM trap（plugin-loader.md §3：Store 未毒化，后续流照常）")
            .into();
    }
    err.into()
}

pub struct WasmPluginMiddleware {
    /// `plugin_name()` 固化名（§7 R-name：Box::leak 一次，生命周期进程级）
    name: &'static str,
    vm: Mutex<WasmVm>,
    opts: crate::PluginLoadOptions,
    stats: PluginStats,
    wants_payload: bool,
}

impl std::fmt::Debug for WasmPluginMiddleware {
    // trait 对象面同款（MiddlewareChain 先例）：以名字/预算/首块声明/计数呈现
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPluginMiddleware")
            .field("name", &self.name)
            .field("fuel", &self.opts.fuel)
            .field("wants_payload", &self.wants_payload)
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

impl WasmPluginMiddleware {
    pub fn new(
        name: &'static str,
        vm: WasmVm,
        opts: crate::PluginLoadOptions,
        wants_payload: bool,
    ) -> Self {
        Self {
            name,
            vm: Mutex::new(vm),
            opts,
            stats: PluginStats::default(),
            wants_payload,
        }
    }

    pub fn stats(&self) -> PluginStatsSnapshot {
        self.stats.snapshot()
    }

    /// `plugin_name()` 固化名（观测面取数：控制面 /plugins/stats 以名标识插件）
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn wants_payload(&self) -> bool {
        self.wants_payload
    }

    /// 单次裁决（全同步）：fuel 重置 → ctx 写入 → on_flow → 决策解析。
    fn invoke(&self, ctx_json: &str) -> Result<PluginDecision> {
        self.stats.calls.fetch_add(1, Ordering::Relaxed);
        // 宿主 panic（如序列化）毒化锁时恢复底层值继续——wasm 调用本身经
        // classify_call_err 转为 Err 不 panic，poison 仅示宿主侧异常；恢复
        // 后 store/memory 状态仍可复用（invoke 每次 set_fuel/重写 ctx）。
        let mut guard = match self.vm.lock() {
            Ok(g) => g,
            Err(p) => {
                tracing::warn!(target: "rillane::plugins", name = self.name, "vm mutex 曾被毒化，恢复使用");
                p.into_inner()
            }
        };
        let WasmVm {
            store,
            alloc_fn,
            on_flow_fn,
            memory,
        } = &mut *guard;
        // 预算按调用计（§2.1）：每调用重置
        store
            .set_fuel(self.opts.fuel)
            .map_err(anyhow::Error::from)
            .context("fuel 预算设置失败（engine 须 consume_fuel(true)）")?;
        let ctx_len = ctx_json.len() as u32;
        let ctx_ptr = alloc_fn
            .call(&mut *store, ctx_len)
            .map_err(|e| classify_call_err(e, &self.stats))?;
        memory
            .write(&mut *store, ctx_ptr as usize, ctx_json.as_bytes())
            .map_err(anyhow::Error::from)
            .context("ctx 写入插件线性内存失败")?;
        let out_ptr = alloc_fn
            .call(&mut *store, DECISION_OUT_CAP)
            .map_err(|e| classify_call_err(e, &self.stats))?;
        let written = on_flow_fn
            .call(&mut *store, (ctx_ptr, ctx_len, out_ptr, DECISION_OUT_CAP))
            .map_err(|e| classify_call_err(e, &self.stats))?;
        if written < 0 {
            bail!("插件 {} 返回错误码 {written}", self.name);
        }
        // 宿主侧上界钳制（§3 内存行）：不信插件返回值
        anyhow::ensure!(
            written <= i32::try_from(DECISION_OUT_CAP).unwrap(),
            "插件 {} 决策长度越界：{written} > {DECISION_OUT_CAP}",
            self.name
        );
        let written = written as usize;
        let mut out = vec![0u8; written];
        memory
            .read(&mut *store, out_ptr as usize, &mut out)
            .map_err(anyhow::Error::from)
            .context("决策读取越界")?;
        serde_json::from_slice(&out)
            .with_context(|| format!("插件 {} 决策 JSON 解析失败", self.name))
    }

    /// ctx JSON（§1.3）：宿主注入 now_ms；wants_payload=1 时 base64 首块。
    fn build_ctx(&self, flow: &Flow, first_chunk: Option<&[u8]>) -> String {
        let ctx = FlowContextJson {
            flow_id: flow.id.as_uuid().to_string(),
            host: &flow.target.host,
            port: flow.target.port,
            proto: match flow.target.proto {
                TargetProto::Tcp => "tcp",
                TargetProto::Udp => "udp",
                TargetProto::Quic => "quic",
            },
            now_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            annotations: &flow.metadata.annotations,
            first_chunk: first_chunk.map(|c| base64::engine::general_purpose::STANDARD.encode(c)),
        };
        serde_json::to_string(&ctx).expect("ctx 序列化不失败（纯 JSON 值类型）")
    }
}

#[async_trait]
impl FlowMiddleware for WasmPluginMiddleware {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn handle(&self, mut flow: Flow) -> Result<Flow> {
        // 首块探测（§2.2）：单次 read 至多 FIRST_CHUNK_CAP；链内首读者假设（§6 偏差 6）
        let first_chunk = if self.wants_payload {
            let mut buf = vec![0u8; FIRST_CHUNK_CAP];
            let n = flow.io.read(&mut buf).await.context("首块探测读失败")?;
            Some(buf[..n].to_vec())
        } else {
            None
        };
        let ctx = self.build_ctx(&flow, first_chunk.as_deref());
        let decision = self.invoke(&ctx)?;
        if decision.is_deny() {
            self.stats.denied.fetch_add(1, Ordering::Relaxed);
            bail!(
                "插件 {} 拒绝流（{}）",
                self.name,
                decision.note.as_deref().unwrap_or("无 note")
            );
        }
        // 注解写面（§1.3 契约同款）
        for (k, v) in &decision.set_annotations {
            flow.metadata.annotations.insert(k.clone(), v.clone());
        }
        for k in &decision.remove_annotations {
            flow.metadata.annotations.remove(k);
        }
        // allow + 探测过 → 回放包装（§2.2）；IoStream blanket impl 自动适配
        if let Some(chunk) = first_chunk {
            flow.io = Box::new(ReplayIo::new(chunk, flow.io));
        }
        Ok(flow)
    }
}
