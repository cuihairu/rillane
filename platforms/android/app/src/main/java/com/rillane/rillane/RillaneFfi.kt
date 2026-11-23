package com.rillane.rillane

/**
 * JNI 桥（Rust 侧 crates/rillane-ffi/src/jni_bridge.rs，符号
 * Java_com_rillane_rillane_RillaneFfi_*）。句柄以 Long 承载指针；0 = 无效/失败。
 */
object RillaneFfi {
    init {
        System.loadLibrary("rillane_ffi")
    }

    /** 版本串（进程级静态） */
    external fun version(): String

    /** 同线程最近一次错误（读后即清；无错误返回 null） */
    external fun lastError(): String?

    /** 以配置 YAML 启动完整 runtime；返回句柄，0 = 失败（取 lastError） */
    external fun start(configYaml: String): Long

    /** 停止并释放句柄（句柄此后不得复用）。0 成功 / -1 失败 */
    external fun stop(handle: Long): Int

    /** 运行状态：1 运行 / 0 停止 / -1 句柄无效 */
    external fun isRunning(handle: Long): Int

    /** 运行统计 JSON（与 rillaned 控制面 /stats 同形字段）；null = 句柄无效 */
    external fun statsJson(handle: Long): String?

    // RIL-150 查询面：与 rillaned 控制面同字段口径（schema_version=1）；
    // 全部 null = 句柄无效（取 lastError）。

    /** 路由概要 JSON（mode/default_node/global_node/direct_node/groups/rules_count） */
    external fun routingJson(handle: Long): String?

    /** 节点 JSON（组实时质量 + 出口节点 name/type + 订阅源） */
    external fun nodesJson(handle: Long): String?

    /** DNS 统计 JSON（/dns/stats 同形；network.dns 缺席 = enabled:false） */
    external fun dnsStatsJson(handle: Long): String?

    /** DNS 解析器 JSON（/dns/resolvers 同形；块缺席 = enabled:false 空形态） */
    external fun dnsResolversJson(handle: Long): String?

    /** 活动/近期连接分页 JSON（/trace/flows 同形信封；limit=0 → error 信封） */
    external fun flowsJson(handle: Long, offset: Long, limit: Long): String?

    /** 单流详情 JSON（/trace/flow 同形；未知/无效 ID = found:false + 稳定码） */
    external fun flowJson(handle: Long, flowId: String): String?

    /** 挂载 TUN fd（所有权移交 Rust，Java 侧 detachFd 后传入）。0 成功 / -1 失败 */
    external fun tunStart(handle: Long, fd: Int): Int

    /** 停 TUN 线程（幂等）。0 成功 / -1 失败 */
    external fun tunStop(handle: Long): Int
}
