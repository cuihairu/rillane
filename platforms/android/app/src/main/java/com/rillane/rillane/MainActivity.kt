package com.rillane.rillane

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * demo 主界面：start（VPN consent → 起 VpnService）/ stop / 状态轮询
 * （FFI statsJson 一秒刷新）。程序化 UI，零布局资源依赖。
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private val handler = Handler(Looper.getMainLooper())

    private val poll = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }

        val title = TextView(this).apply {
            text = "RILLANE 移动端 demo（rillane-ffi ${safeVersion()}）"
            textSize = 18f
        }
        status = TextView(this).apply {
            textSize = 13f
            setTextColor(Color.DKGRAY)
            setPadding(0, 32, 0, 32)
            text = "未启动"
        }

        val startBtn = Button(this).apply {
            text = "启动 VPN（建 tun + 一轮流量面）"
            setOnClickListener { startVpn() }
        }
        val stopBtn = Button(this).apply {
            text = "停止"
            setOnClickListener {
                startService(Intent(this@MainActivity, RillaneVpnService::class.java).apply {
                    action = RillaneVpnService.ACTION_STOP
                })
            }
        }

        root.addView(title)
        root.addView(status)
        root.addView(startBtn)
        root.addView(stopBtn)
        setContentView(root)

        // 自动化入口：`adb shell am start -n com.rillane.rillane/.MainActivity --ez autostart true`
        // 直接走 startVpn()（配合 appops ACTIVATE_VPN allow 免弹窗，CI/模拟器验收路径）
        if (intent?.getBooleanExtra("autostart", false) == true) {
            startVpn()
        }
    }

    private fun safeVersion(): String = try { RillaneFfi.version() } catch (t: Throwable) { "未加载" }

    private fun startVpn() {
        // consent 弹窗一次放行后 prepare 恒 null；CI/自动化可用
        // `adb shell appops set com.rillane.rillane ACTIVATE_VPN allow` 免弹窗
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_CONSENT)
        } else {
            connect()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CONSENT && resultCode == RESULT_OK) {
            connect()
        }
    }

    private fun connect() {
        startService(Intent(this, RillaneVpnService::class.java))
    }

    private fun refreshStatus() {
        val h = RillaneVpnService.ffiHandle
        status.text = when {
            h == 0L -> "未启动"
            else -> {
                val running = RillaneFfi.isRunning(h) == 1
                val stats = RillaneFfi.statsJson(h)
                buildString {
                    append(if (running) "运行中" else "已停止")
                    if (stats != null) append("\n$stats")
                    RillaneFfi.lastError()?.let { append("\nlastError: $it") }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(poll)
    }

    override fun onPause() {
        handler.removeCallbacks(poll)
        super.onPause()
    }

    companion object {
        private const val REQUEST_CONSENT = 1
    }
}
