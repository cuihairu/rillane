//! 载入器（plugin-loader.md §2.1）：进程级 engine 单例（D-10 同法——
//! 编译器/JIT 全局一份，插件间共享；每插件独立 Store/Instance）。

use std::{
    path::Path,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, Result};
use seep_core::FlowMiddleware;

use crate::{
    abi::{
        EXPORT_ALLOC, EXPORT_MEMORY, EXPORT_ON_FLOW, EXPORT_PLUGIN_NAME, EXPORT_WANTS_PAYLOAD,
        PLUGIN_NAME_CAP,
    },
    plugin::{WasmPluginMiddleware, WasmVm},
    PluginLoadOptions,
};

/// 进程级 engine 单例（§1.1）：fuel 预算是隔离面（§3），engine 全局开启
/// consume_fuel，per-call `set_fuel` 重置（plugin.rs invoke）。
///
/// 存 `Result`：engine 初始化失败（平台不支持 JIT/编译器 feature 缺失等）时
/// 不 panic（原 `LazyLock::expect` 首插件加载即进程级崩溃），而是让加载调用
/// 返回 Err——插件为可选特性，失败应可观测可降级而非杀进程。
static ENGINE: LazyLock<Result<wasmtime::Engine, String>> = LazyLock::new(|| {
    let mut cfg = wasmtime::Config::new();
    cfg.consume_fuel(true);
    wasmtime::Engine::new(&cfg).map_err(|e| format!("wasmtime engine 初始化失败: {e}"))
});

fn engine() -> Result<&'static wasmtime::Engine> {
    ENGINE.as_ref().map_err(|e| anyhow::anyhow!(e.clone()))
}

/// 从文件载入插件 → `FlowMiddleware` 适配器（同步调用；JIT 编译发生在本调用，
/// 位于 build_middleware_chain 装配期，不占运行期）。
pub fn load_plugin(path: &Path, opts: PluginLoadOptions) -> Result<Arc<dyn FlowMiddleware>> {
    Ok(load_plugin_with_stats(path, opts)?.0)
}

/// 从文件载入并同时返回擦除前后两个句柄（观测轮：trait 对象入链、
/// 具体类型旁路给 Runtime 计数面取数——同一实例，不二次 JIT）。
pub fn load_plugin_with_stats(
    path: &Path,
    opts: PluginLoadOptions,
) -> Result<(Arc<dyn FlowMiddleware>, Arc<WasmPluginMiddleware>)> {
    let bytes = std::fs::read(path).with_context(|| format!("读取插件文件 {path:?} 失败"))?;
    let mw =
        load_plugin_from_bytes(&bytes, opts).with_context(|| format!("载入插件 {path:?} 失败"))?;
    let erased: Arc<dyn FlowMiddleware> = mw.clone();
    Ok((erased, mw))
}

/// 从内存载入（§4.1：单测内联 WAT 与生产二进制同一 ABI 面）。
/// 返回具体适配器类型（stats/首块声明可观测；load_plugin 侧再擦除为 trait 对象）。
pub fn load_plugin_from_bytes(
    bytes: &[u8],
    opts: PluginLoadOptions,
) -> Result<Arc<WasmPluginMiddleware>> {
    let engine = engine().context("获取 wasmtime 引擎失败")?;
    // wasmtime 49 自有 Error 类型：map_err 过桥 anyhow 后再挂上下文
    let module = wasmtime::Module::new(engine, bytes)
        .map_err(anyhow::Error::from)
        .context("wasm 模块编译失败（坏 magic 或非法 wat）")?;
    let mut store = wasmtime::Store::new(engine, ());
    // 载入期探测调用（wants_payload/plugin_name）的燃料池：consume_fuel 引擎下
    // store 初始 fuel=0，任何调用即 OutOfFuel——此处放开；每调用预算重置语义
    // 在 invoke（plugin.rs §2.1），不归载入期
    store
        .set_fuel(u64::MAX)
        .map_err(anyhow::Error::from)
        .context("载入期 fuel 池设置失败")?;
    // 零 import 面（§0 载具裁决：纯计算、无 WASI）——有 import 在此拦截
    let instance = wasmtime::Instance::new(&mut store, &module, &[])
        .map_err(anyhow::Error::from)
        .context("插件实例化失败（含未满足 import？插件须零 import）")?;
    let memory = instance
        .get_memory(&mut store, EXPORT_MEMORY)
        .context("缺 memory 导出（plugin-loader.md §1.2 ABI）")?;
    let alloc_fn = instance
        .get_typed_func::<u32, u32>(&mut store, EXPORT_ALLOC)
        .map_err(anyhow::Error::from)
        .context("缺 alloc 导出（plugin-loader.md §1.2 ABI）")?;
    let on_flow_fn = instance
        .get_typed_func::<(u32, u32, u32, u32), i32>(&mut store, EXPORT_ON_FLOW)
        .map_err(anyhow::Error::from)
        .context("缺 on_flow 导出（plugin-loader.md §1.2 ABI）")?;
    // wants_payload 可选（§1.2：缺席视为 0）——先探导出存在再取类型化句柄
    let wants_payload = match instance.get_export(&mut store, EXPORT_WANTS_PAYLOAD) {
        Some(_) => {
            instance
                .get_typed_func::<(), u32>(&mut store, EXPORT_WANTS_PAYLOAD)
                .map_err(anyhow::Error::from)
                .context("wants_payload 导出签名须为 () -> u32")?
                .call(&mut store, ())
                .map_err(anyhow::Error::from)
                .context("wants_payload 调用失败")?
                != 0
        }
        None => false,
    };
    let name_fn = instance
        .get_typed_func::<(), u32>(&mut store, EXPORT_PLUGIN_NAME)
        .map_err(anyhow::Error::from)
        .context("缺 plugin_name 导出（plugin-loader.md §1.2 ABI）")?;
    let name_ptr = name_fn.call(&mut store, ())?;
    let name = read_cstr(&mut store, &memory, name_ptr).context("plugin_name 读取失败")?;
    // §7 R-name：载入一次、生命周期进程级——泄漏量 = 插件数 × 名字长
    let name: &'static str = Box::leak(name.into_boxed_str());
    Ok(Arc::new(WasmPluginMiddleware::new(
        name,
        WasmVm {
            store,
            alloc_fn,
            on_flow_fn,
            memory,
        },
        opts,
        wants_payload,
    )))
}

/// 读 NUL 结尾 UTF-8 串（上限 PLUGIN_NAME_CAP，防裸奔模块无界读）。
fn read_cstr(
    store: &mut wasmtime::Store<()>,
    memory: &wasmtime::Memory,
    ptr: u32,
) -> Result<String> {
    let mut buf = [0u8; PLUGIN_NAME_CAP];
    memory
        .read(store, ptr as usize, &mut buf)
        .map_err(anyhow::Error::from)
        .context("越界（内存过小或指针非法）")?;
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .context("plugin_name 未 NUL 结尾或超 256 字节")?;
    String::from_utf8(buf[..end].to_vec()).context("plugin_name 非合法 UTF-8")
}
