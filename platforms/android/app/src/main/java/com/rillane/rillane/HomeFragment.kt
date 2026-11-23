package com.rillane.rillane

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.snackbar.Snackbar
import org.json.JSONObject

/**
 * 首页（RIL-150）：VPN 状态卡（StateBus 即时同步 + 触觉/读屏播报）、
 * 选路模式只读面（routing_json；切模式需配置事务，移动端只读）、
 * 用量面板（1s statsJson 轮询，缺席字段不落 0）、快捷工具。
 */
class HomeFragment : Fragment() {
    private var _stateText: TextView? = null
    private var _networkText: TextView? = null
    private var _usageText: TextView? = null
    private var _modeGroup: MaterialButtonToggleGroup? = null
    private var _startBtn: MaterialButton? = null
    private var _stopBtn: MaterialButton? = null

    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            refreshUsage()
            refreshMode()
            handler.postDelayed(this, 1000)
        }
    }
    private var unsubscribe: (() -> Unit)? = null
    private var lastAnnounced: VpnState? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        val root = inflater.inflate(R.layout.fragment_home, container, false)
        _stateText = root.findViewById(R.id.vpn_state_text)
        _networkText = root.findViewById(R.id.vpn_network_text)
        _usageText = root.findViewById(R.id.usage_text)
        _modeGroup = root.findViewById(R.id.mode_group)
        _startBtn = root.findViewById(R.id.start_vpn_btn)
        _stopBtn = root.findViewById(R.id.stop_vpn_btn)

        _startBtn?.setOnClickListener {
            (activity as? MainActivity)?.let { main ->
                // VPN consent 在 Activity 层统一（弹窗/结果回传）
                val consent = android.net.VpnService.prepare(main)
                if (consent != null) {
                    main.startActivityForResult(consent, 1)
                } else {
                    main.connectNow()
                }
            }
        }
        _stopBtn?.setOnClickListener {
            context?.startService(
                Intent(context, RillaneVpnService::class.java).apply {
                    action = RillaneVpnService.ACTION_STOP
                },
            )
        }
        root.findViewById<MaterialButton>(R.id.go_nodes_btn)?.setOnClickListener {
            (activity as? MainActivity)?.showTab(R.id.nav_nodes)
        }
        root.findViewById<MaterialButton>(R.id.go_connections_btn)?.setOnClickListener {
            (activity as? MainActivity)?.showTab(R.id.nav_connections)
        }
        root.findViewById<MaterialButton>(R.id.dev_tools_btn)?.setOnClickListener {
            Snackbar.make(root, R.string.home_dev_unavailable, Snackbar.LENGTH_SHORT).show()
        }
        return root
    }

    override fun onStart() {
        super.onStart()
        unsubscribe = StateBus.subscribe { snap ->
            renderState(snap)
            // 读屏：状态变化即时播报（非颜色/非视觉依赖）
            if (snap.state != lastAnnounced) {
                lastAnnounced = snap.state
                _stateText?.announceForAccessibility(stateLabel(snap.state))
            }
        }
        handler.post(poll)
    }

    override fun onStop() {
        unsubscribe?.invoke()
        unsubscribe = null
        handler.removeCallbacks(poll)
        super.onStop()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _stateText = null
        _networkText = null
        _usageText = null
        _modeGroup = null
        _startBtn = null
        _stopBtn = null
    }

    private fun renderState(snap: VpnSnapshot) {
        val text = _stateText ?: return
        val label = stateLabel(snap.state)
        text.text = label
        // 状态色 + 文字双通道（不靠颜色唯一传达）
        val colorRes = when (snap.state) {
            VpnState.CONNECTED -> R.color.status_connected
            VpnState.ERROR -> R.color.status_error
            VpnState.REVOKED -> R.color.status_revoked
            else -> R.color.status_disconnected
        }
        text.setTextColor(resources.getColor(colorRes, null))
        // 读屏状态描述（uiautomator stateDescription 可见；ViewCompat 兼容
        // minSdk 24——API<30 no-op，API30+ 生效）
        ViewCompat.setStateDescription(
            text, label + (snap.reason?.let { "（$it）" } ?: ""),
        )
        _networkText?.text = getString(R.string.network_label) + ": " + snap.networkType
        val h = RillaneVpnService.ffiHandle
        val connected = h != 0L && RillaneFfi.isRunning(h) == 1
        _startBtn?.isEnabled = !connected
        _stopBtn?.isEnabled = connected
    }

    /** 用量面板：缺席字段显示「未知」不落 0（statsJson 恒含键；句柄无效 = 无数据） */
    private fun refreshUsage() {
        val usage = _usageText ?: return
        val h = RillaneVpnService.ffiHandle
        if (h == 0L) {
            usage.text = getString(R.string.home_no_data)
            return
        }
        val raw = try {
            RillaneFfi.statsJson(h)
        } catch (t: Throwable) {
            null
        }
        if (raw == null) {
            usage.text = getString(R.string.home_no_data)
            return
        }
        usage.text = formatStats(raw)
    }

    /** 选路模式只读面：routing_json().mode 高亮，三个钮恒 disabled（tap 不生效） */
    private fun refreshMode() {
        val group = _modeGroup ?: return
        val h = RillaneVpnService.ffiHandle
        if (h == 0L) return
        val raw = try {
            RillaneFfi.routingJson(h)
        } catch (t: Throwable) {
            null
        } ?: return
        val mode = try {
            JSONObject(raw).optString("mode", "rule")
        } catch (t: Throwable) {
            "rule"
        }
        val checkedId = when (mode) {
            "global" -> R.id.mode_global
            "direct" -> R.id.mode_direct
            else -> R.id.mode_rule
        }
        if (group.checkedButtonId != checkedId) {
            group.check(checkedId)
        }
        // 只读：三钮全部禁用（caption 已注明原因）
        listOf(R.id.mode_rule, R.id.mode_global, R.id.mode_direct).forEach { id ->
            group.findViewById<MaterialButton>(id)?.isEnabled = false
        }
    }

    private fun formatStats(raw: String): String = try {
        val o = JSONObject(raw)
        buildString {
            append("运行 ").append(o.optLong("uptime_seconds", -1).let {
                if (it < 0) "未知" else "%d:%02d:%02d".format(it / 3600, (it % 3600) / 60, it % 60)
            })
            append("\n活动连接 ").append(o.optLong("active_connections", -1).let {
                if (it < 0) "未知" else it.toString()
            })
            append(" / 总计 ").append(o.optLong("total_connections", -1).let {
                if (it < 0) "未知" else it.toString()
            })
            append("\n上行 ").append(formatBytes(o.optLong("bytes_uploaded", -1)))
            append("　下行 ").append(formatBytes(o.optLong("bytes_downloaded", -1)))
            append("\n错误 ").append(o.optLong("error_count", -1).let {
                if (it < 0) "未知" else it.toString()
            })
        }
    } catch (t: Throwable) {
        getString(R.string.home_no_data)
    }

    private fun formatBytes(v: Long): String = if (v < 0) "未知" else when {
        v >= 1 shl 30 -> "%.1f GiB".format(v.toDouble() / (1 shl 30))
        v >= 1 shl 20 -> "%.1f MiB".format(v.toDouble() / (1 shl 20))
        v >= 1 shl 10 -> "%.1f KiB".format(v.toDouble() / (1 shl 10))
        else -> "$v B"
    }

    private fun stateLabel(state: VpnState): String = when (state) {
        VpnState.DISCONNECTED -> getString(R.string.state_disconnected)
        VpnState.CONNECTING -> getString(R.string.state_connecting)
        VpnState.CONNECTED -> getString(R.string.state_connected)
        VpnState.ERROR -> getString(R.string.state_error)
        VpnState.REVOKED -> getString(R.string.state_revoked)
    }
}
