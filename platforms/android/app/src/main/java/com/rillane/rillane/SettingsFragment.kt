package com.rillane.rillane

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.snackbar.Snackbar
import org.json.JSONObject

/**
 * 设置 Tab（RIL-150）：网络与 DNS 卡——dnsStatsJson + dnsResolversJson。
 * 无 network.dns 块 → enabled:false →「DNS 未启用」如实。待应用变更 →
 * 控制面配置事务（移动端只读，Snackbar 说明）。
 */
class SettingsFragment : Fragment() {
    private var statsText: TextView? = null
    private var resolversText: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        val root = inflater.inflate(R.layout.fragment_settings, container, false)
        statsText = root.findViewById(R.id.dns_stats_text)
        resolversText = root.findViewById(R.id.dns_resolvers_text)
        root.findViewById<MaterialButton>(R.id.pending_changes_btn)?.setOnClickListener {
            Snackbar.make(root, R.string.settings_tx_unavailable, Snackbar.LENGTH_SHORT).show()
        }
        return root
    }

    override fun onStart() {
        super.onStart()
        refresh()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        statsText = null
        resolversText = null
    }

    private fun refresh() {
        val h = RillaneVpnService.ffiHandle
        if (h == 0L) {
            statsText?.text = getString(R.string.settings_dns_disabled)
            resolversText?.text = getString(R.string.settings_dns_disabled)
            return
        }
        renderStats(try { RillaneFfi.dnsStatsJson(h) } catch (t: Throwable) { null })
        renderResolvers(try { RillaneFfi.dnsResolversJson(h) } catch (t: Throwable) { null })
    }

    private fun renderStats(raw: String?) {
        val text = statsText ?: return
        if (raw == null) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        val o = try {
            JSONObject(raw)
        } catch (t: Throwable) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        if (!o.optBoolean("enabled", false)) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        text.text = buildString {
            append("监听: ").append(o.optString("listen", "?")).append("\n")
            append("查询 ").append(o.optLong("total_queries", 0))
            append(" · 命中 ").append(o.optLong("cache_hits", 0))
            append("（%s）".format("%.1f%%".format(o.optDouble("cache_hit_rate", 0.0) * 100)))
            append("\n未命中 ").append(o.optLong("cache_misses", 0))
            append(" · 上游失败 ").append(o.optLong("upstream_failures", 0))
            append("\n污染疑似 ").append(o.optLong("pollution_suspected", 0))
            append(" · 国内查询 ").append(o.optLong("domestic_queries", 0))
            append(" · 可信查询 ").append(o.optLong("trusted_queries", 0))
        }
    }

    private fun renderResolvers(raw: String?) {
        val text = resolversText ?: return
        if (raw == null) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        val o = try {
            JSONObject(raw)
        } catch (t: Throwable) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        if (!o.optBoolean("enabled", false)) {
            text.text = getString(R.string.settings_dns_disabled)
            return
        }
        text.text = buildString {
            append("国内: ").append(joinList(o, "domestic")).append("\n")
            append("可信: ").append(joinList(o, "trusted")).append("\n")
            append("引导: ").append(joinList(o, "bootstrap")).append("\n")
            append("引导模式: ").append(o.optString("bootstrap_mode", "?"))
            append(" · 兜底: ").append(o.optString("default_group", "?"))
            append("\n防污染: ").append(o.optString("anti_poison", "?"))
            append(" · 超时 ").append(o.optLong("timeout_ms", 0)).append("ms")
            append(" · 规则 ").append(o.optLong("rules", 0)).append(" 条")
        }
    }

    private fun joinList(o: JSONObject, key: String): String {
        val arr = o.optJSONArray(key) ?: return "（无）"
        return if (arr.length() == 0) "（无）" else (0 until arr.length()).joinToString(" ") { arr.optString(it) }
    }
}
