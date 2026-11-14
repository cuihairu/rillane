package com.rillane.rillane

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * VpnService 面：establish() 建 TUN → fd detach 后交 Rust（rillane-ffi
 * tun_start 持有并跑最小数据通路）。
 *
 * demo 路由面：仅接管 10.111.0.0/24 测试网段（ping 10.111.0.1 走隧道，
 * ICMP echo 由 FFI 应答）；0.0.0.0/0 全局接管随 P1-2 TunIngress 真实
 * 代理路径落地后再开（现开会导致流量黑洞）。
 */
class RillaneVpnService : VpnService() {
    companion object {
        private const val TAG = "RillaneVpn"
        const val ACTION_STOP = "com.rillane.rillane.STOP"

        /** FFI 句柄（服务生命周期内复用；0 = 未启动） */
        @Volatile
        var ffiHandle: Long = 0
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        startVpn()
        return START_NOT_STICKY
    }

    private fun startVpn() {
        // runtime 一次起、跨重建复用；config 走 assets（免存储权限样板）
        if (ffiHandle == 0L || RillaneFfi.isRunning(ffiHandle) != 1) {
            if (ffiHandle != 0L) {
                RillaneFfi.stop(ffiHandle)
                ffiHandle = 0
            }
            val config = assets.open("rillane.yaml").bufferedReader().use { it.readText() }
            ffiHandle = RillaneFfi.start(config)
            if (ffiHandle == 0L) {
                Log.e(TAG, "rillane runtime 启动失败: ${RillaneFfi.lastError() ?: "未知错误"}")
                stopSelf()
                return
            }
            Log.i(TAG, "rillane runtime 已启动 (rillane-ffi ${RillaneFfi.version()})")
        }

        val tun: ParcelFileDescriptor = Builder()
            .addAddress("10.111.0.2", 24)
            .addRoute("10.111.0.0", 24) // demo 只接管测试网段，见类注释
            .setMtu(1500)
            .setSession("RILLANE demo")
            .establish()
            ?: run {
                Log.e(TAG, "establish() 返回 null（VPN consent 未放行或接口异常）")
                stopSelf()
                return
            }

        // 一轮流量的关键交接：detachFd 后所有权归 Rust，JNI tunStart 持有
        // 并起 ICMP echo 轮转（crates/rillane-ffi/src/tun.rs）
        val fd = tun.detachFd()
        if (RillaneFfi.tunStart(ffiHandle, fd) != 0) {
            Log.e(TAG, "TUN 挂载失败: ${RillaneFfi.lastError() ?: "未知错误"}")
            stopSelf()
            return
        }
        Log.i(TAG, "TUN 已挂载（fd=$fd），ping 10.111.0.1 可验一轮流量")
    }

    private fun stopVpn() {
        if (ffiHandle != 0L) {
            RillaneFfi.stop(ffiHandle) // 内部先停 TUN 线程（fd 随之关闭）
            ffiHandle = 0
            Log.i(TAG, "rillane runtime 已停止")
        }
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
