package com.rillane.rillane

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * VpnService 面（RIL-150）：establish() 建 TUN → fd detach 后交 Rust
 * （rillane-ffi tun_start 持有并跑最小数据通路）。
 *
 * 生命周期（验收核心）：
 * - 前台服务：onStartCommand 第一动作 startForeground（CONNECTED_DEVICE 类型，
 *   渠道 rillane_vpn/IMPORTANCE_LOW）。
 * - onRevoke：系统撤销授权 → 先关 TUN 再停 runtime（绝不事后触碰 fd）→
 *   stopForeground → StateBus REVOKED → stopSelf。
 * - onTrimMemory：**不拆 VPN**（低内存提示非终止；拆了会掉连），只重发
 *   StateBus 快照让 UI 重读 FFI。
 * - 切网：registerDefaultNetworkCallback → 网络标签（忽略 VPN 自身）→ StateBus。
 *
 * demo 路由面：仅接管 10.111.0.0/24 测试网段（ping 10.111.0.1 走隧道，
 * ICMP echo 由 FFI 应答）；0.0.0.0/0 全局接管随 P1-2 TunIngress 真实
 * 代理路径落地后再开。**不引入 UID 名单**（无 addAllowedApplication）。
 */
class RillaneVpnService : VpnService() {
    companion object {
        private const val TAG = "RillaneVpn"
        const val ACTION_STOP = "com.rillane.rillane.STOP"
        private const val CHANNEL_ID = "rillane_vpn"
        private const val NOTIFICATION_ID = 1001

        /** FFI 句柄（服务生命周期内复用；0 = 未启动） */
        @Volatile
        var ffiHandle: Long = 0
    }

    private var tunStarted = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 前台服务第一动作（通知渠道就绪后立即置前台——FGS 类型 API 29+）
        startForegroundCompat(buildNotification())

        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopForegroundCompat()
            StateBus.update(state = VpnState.DISCONNECTED, reason = "user")
            stopSelf()
            return START_NOT_STICKY
        }

        StateBus.update(state = VpnState.CONNECTING)
        startVpn()
        return START_NOT_STICKY
    }

    /** 系统撤销 VPN 授权（用户关闭 VPN / appops deny）：完整有序收尾 */
    override fun onRevoke() {
        Log.i(TAG, "onRevoke：授权被系统撤销")
        stopVpn()
        stopForegroundCompat()
        StateBus.update(state = VpnState.REVOKED, reason = "revoked")
        stopSelf()
    }

    /** 低内存提示：非终止信号——不拆 VPN（拆了会掉连），只重发快照 */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        Log.i(TAG, "onTrimMemory(level=$level)：不拆 VPN，仅重发状态快照")
        StateBus.publish()
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
                StateBus.update(state = VpnState.ERROR, reason = RillaneFfi.lastError())
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
                StateBus.update(state = VpnState.ERROR, reason = "establish 失败")
                stopSelf()
                return
            }

        // 一轮流量的关键交接：detachFd 后所有权归 Rust，JNI tunStart 持有
        // 并起 ICMP echo 轮转（crates/rillane-ffi/src/tun.rs）
        val fd = tun.detachFd()
        if (RillaneFfi.tunStart(ffiHandle, fd) != 0) {
            Log.e(TAG, "TUN 挂载失败: ${RillaneFfi.lastError() ?: "未知错误"}")
            StateBus.update(state = VpnState.ERROR, reason = RillaneFfi.lastError())
            stopSelf()
            return
        }
        tunStarted = true
        StateBus.update(state = VpnState.CONNECTED)
        Log.i(TAG, "TUN 已挂载（fd=$fd），ping 10.111.0.1 可验一轮流量")
    }

    /** 有序收尾：先停 TUN（join 线程、fd 随线程关闭）再停 runtime——绝不事后触碰 fd */
    private fun stopVpn() {
        if (ffiHandle != 0L) {
            RillaneFfi.stop(ffiHandle) // 内部先停 TUN 线程（fd 随之关闭）
            ffiHandle = 0
            tunStarted = false
            Log.i(TAG, "rillane runtime 已停止")
        }
    }

    override fun onDestroy() {
        stopVpn() // 幂等兜底
        unregisterNetworkCallback()
        super.onDestroy()
    }

    // ------------------------------------------------------------------
    // 前台服务通知
    // ------------------------------------------------------------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val launchIntent = Intent(this, MainActivity::class.java)
        val contentIntent = PendingIntent.getActivity(
            this, 0, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("RILLANE VPN 已连接")
            .setContentText("接管 10.111.0.0/24（demo 数据面）")
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // ------------------------------------------------------------------
    // 切网标签（忽略 VPN 自身；UI 经 StateBus 即时同步）
    // ------------------------------------------------------------------

    private var connectivityManager: ConnectivityManager? = null
    @Volatile
    private var lastNetworkLabel: String = "未知"

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager = cm
        try {
            cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = refreshNetworkLabel(cm)
                override fun onLost(network: Network) = refreshNetworkLabel(cm)
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    refreshNetworkLabel(cm)
            })
        } catch (t: Throwable) {
            Log.w(TAG, "registerDefaultNetworkCallback 失败：${t.message}")
        }
        refreshNetworkLabel(cm)
    }

    private fun refreshNetworkLabel(cm: ConnectivityManager) {
        val label = networkTypeLabel(cm)
        if (label != lastNetworkLabel) {
            lastNetworkLabel = label
            StateBus.update(networkType = label)
        }
    }

    /** 当前默认网络标签；忽略 VPN 自身（TRANSPORT_VPN），避免显示「VPN」 */
    private fun networkTypeLabel(cm: ConnectivityManager): String {
        val network = cm.activeNetwork ?: return "无网络"
        val caps = cm.getNetworkCapabilities(network) ?: return "未知"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "蜂窝"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "以太网"
            else -> "其他"
        }
    }

    private fun unregisterNetworkCallback() {
        // DefaultNetworkCallback 随服务销毁由系统注销；此处无需显式 unregister
    }
}
