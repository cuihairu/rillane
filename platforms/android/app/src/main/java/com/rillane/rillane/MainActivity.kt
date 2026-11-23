package com.rillane.rillane

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.rillane.rillane.databinding.ActivityMainBinding

/**
 * 主界面（RIL-150）：四 Tab（首页/节点/连接/设置）Material 3。
 * 承载 BottomNavigationView + Fragment 容器；VPN consent 弹窗、FGS 启动
 * 与 POST_NOTIFICATIONS 运行时请求；autostart 自动化入口保留。
 */
class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    private val home = HomeFragment()
    private val nodes = NodesFragment()
    private val connections = ConnectionsFragment()
    private val settings = SettingsFragment()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.bottomNav.setOnItemSelectedListener { item ->
            switchTab(item.itemId)
            true
        }
        if (savedInstanceState == null) {
            binding.bottomNav.selectedItemId = R.id.nav_home
        }

        requestNotificationPermissionIfNeeded()

        // 自动化入口：`adb shell am start -n com.rillane.rillane/.MainActivity --ez autostart true`
        // 直接走 startVpn()（配合 appops ACTIVATE_VPN allow 免弹窗，CI/模拟器验收路径）
        if (intent?.getBooleanExtra("autostart", false) == true) {
            startVpn()
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun switchTab(itemId: Int): Boolean {
        val fragment = when (itemId) {
            R.id.nav_home -> home
            R.id.nav_nodes -> nodes
            R.id.nav_connections -> connections
            R.id.nav_settings -> settings
            else -> return false
        }
        supportFragmentManager.beginTransaction().apply {
            // show/hide 保留各 Tab 状态（切换不回跳回顶部）
            listOf(home, nodes, connections, settings).forEach { f ->
                if (f.isAdded) hide(f)
            }
            if (fragment.isAdded) {
                show(fragment)
            } else {
                add(R.id.fragment_container, fragment, fragmentTag(itemId))
            }
        }.commit()
        return true
    }

    private fun fragmentTag(itemId: Int): String = when (itemId) {
        R.id.nav_home -> "home"
        R.id.nav_nodes -> "nodes"
        R.id.nav_connections -> "connections"
        else -> "settings"
    }

    /** 首页快捷工具跳 Tab */
    fun showTab(itemId: Int) {
        binding.bottomNav.selectedItemId = itemId
    }

    private fun startVpn() {
        // consent 弹窗一次放行后 prepare 恒 null；CI/自动化可用
        // `adb shell appops set com.rillane.rillane ACTIVATE_VPN allow` 免弹窗
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_CONSENT)
        } else {
            connectNow()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CONSENT && resultCode == RESULT_OK) {
            connectNow()
        }
    }

    /** 启动 VPN 前台服务（HomeFragment 按钮/consent 回传共用入口） */
    fun connectNow() {
        val intent = Intent(this, RillaneVpnService::class.java)
        // Android 12+ 前台服务从后台启动限制：ContextCompat.startForegroundService
        // 保证应用处前台（点击/自动化触发）时合法
        androidx.core.content.ContextCompat.startForegroundService(this, intent)
    }

    companion object {
        private const val REQUEST_CONSENT = 1
    }
}
