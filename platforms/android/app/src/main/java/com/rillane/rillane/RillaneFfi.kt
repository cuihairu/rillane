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

    /** 挂载 TUN fd（所有权移交 Rust，Java 侧 detachFd 后传入）。0 成功 / -1 失败 */
    external fun tunStart(handle: Long, fd: Int): Int

    /** 停 TUN 线程（幂等）。0 成功 / -1 失败 */
    external fun tunStop(handle: Long): Int
}
