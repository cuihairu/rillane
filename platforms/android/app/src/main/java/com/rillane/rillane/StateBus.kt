package com.rillane.rillane

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CopyOnWriteArrayList

/** VPN 生命周期状态（REVOKED = 系统撤销授权，与 DISCONNECTED 区分） */
enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, ERROR, REVOKED }

/** UI 即时同步快照（状态 + 当前网络标签 + 触发原因） */
data class VpnSnapshot(
    val state: VpnState,
    val networkType: String,
    val reason: String?
)

/**
 * 进程内状态总线：VpnService 生命周期/网络切换即时同步 UI（1s 轮询只用于
 * 用量面板）。监听器在主线程派发；订阅立即投递当前快照（首帧不留空白）。
 */
object StateBus {
    @Volatile
    var snapshot: VpnSnapshot = VpnSnapshot(VpnState.DISCONNECTED, "未知", null)
        private set

    private val listeners = CopyOnWriteArrayList<(VpnSnapshot) -> Unit>()
    private val handler = Handler(Looper.getMainLooper())

    /** 更新快照（null 字段保持原值；state 变化时 reason 重置） */
    fun update(state: VpnState? = null, networkType: String? = null, reason: String? = null) {
        val next = VpnSnapshot(
            state = state ?: snapshot.state,
            networkType = networkType ?: snapshot.networkType,
            reason = if (state != null) reason else snapshot.reason,
        )
        if (next == snapshot) return
        snapshot = next
        handler.post { listeners.forEach { it(next) } }
    }

    /** 订阅快照（主线程回调；返回退订函数） */
    fun subscribe(onSnapshot: (VpnSnapshot) -> Unit): () -> Unit {
        listeners.add(onSnapshot)
        onSnapshot(snapshot)
        return { listeners.remove(onSnapshot) }
    }

    /** 重发当前快照（低内存提示等场景：UI 重读 FFI，不改状态） */
    fun publish() {
        handler.post { listeners.forEach { it(snapshot) } }
    }
}
