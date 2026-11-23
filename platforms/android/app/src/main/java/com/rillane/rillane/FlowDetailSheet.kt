package com.rillane.rillane

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.isVisible
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import org.json.JSONArray
import org.json.JSONObject

/**
 * 连接详情（RIL-150）：flowJson(id) 渲染——命中 = 轨迹字段 + 事件；
 * 未知/无效 ID = found:false + 稳定码 + 收集器计数（从不「未发包」）。
 */
class FlowDetailSheet : BottomSheetDialogFragment() {
    private var flowId: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        flowId = arguments?.getString(ARG_ID).orEmpty()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? = inflater.inflate(R.layout.sheet_flow_detail, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val title = view.findViewById<TextView>(R.id.flow_detail_title)
        val body = view.findViewById<TextView>(R.id.flow_detail_body)
        val eventsTitle = view.findViewById<TextView>(R.id.flow_events_title)
        val eventsText = view.findViewById<TextView>(R.id.flow_events_text)
        view.findViewById<View>(R.id.flow_close_btn).setOnClickListener { dismiss() }

        title.text = getString(R.string.flow_detail_title) + ": $flowId"

        val h = RillaneVpnService.ffiHandle
        val raw = if (h != 0L) {
            try {
                RillaneFfi.flowJson(h, flowId)
            } catch (t: Throwable) {
                null
            }
        } else null
        if (raw == null) {
            body.text = "句柄无效：${RillaneFfi.lastError() ?: "未知错误"}"
            eventsTitle.isVisible = false
            eventsText.isVisible = false
            return
        }
        val o = try {
            JSONObject(raw)
        } catch (t: Throwable) {
            body.text = "响应解析失败"
            eventsTitle.isVisible = false
            eventsText.isVisible = false
            return
        }
        if (!o.optBoolean("found", false)) {
            val absence = o.optJSONObject("absence") ?: JSONObject()
            body.text = buildString {
                append("未找到该流\n")
                append("原因码: ").append(absence.optString("code", "未知")).append("\n")
                append("说明: ").append(absence.optString("note", "")).append("\n")
                val collector = absence.optJSONObject("collector")
                if (collector != null) {
                    append("采集器: 活动 ").append(collector.optLong("active_traces", 0))
                    append(" · 已逐出 ").append(collector.optLong("traces_dropped_overflow", 0))
                    append(" · 已过期 ").append(collector.optLong("traces_expired", 0))
                }
            }
            eventsTitle.isVisible = false
            eventsText.isVisible = false
            return
        }
        val trace = o.optJSONObject("trace") ?: JSONObject()
        val events = trace.optJSONArray("events") ?: JSONArray()
        body.text = buildString {
            append("流 ID: ").append(trace.optString("flow", flowId)).append("\n")
            append("起止语义: ").append(trace.optString("origin", "?")).append("\n")
            append("代际: ").append(trace.optString("generation", "?")).append("\n")
            append("终态: ").append(if (trace.optBoolean("closed", false)) "是" else "否").append("\n")
            append("事件数: ").append(events.length())
        }
        val eventLines = StringBuilder()
        for (i in 0 until events.length()) {
            val e = events.optJSONObject(i) ?: continue
            eventLines.append("[${e.optLong("seq", 0)}] ")
                .append(e.optString("stage", "?"))
                .append(" ")
                .append(e.optString("evidence", "?"))
                .append(" ").append(e.optString("code", ""))
                .append("\n")
            e.optString("detail", "").takeIf { it.isNotEmpty() }?.let {
                eventLines.append("    ").append(it).append("\n")
            }
        }
        eventsText.text = if (eventLines.isEmpty()) "（无事件）" else eventLines.toString()
    }

    companion object {
        private const val ARG_ID = "flow_id"

        fun newInstance(flowId: String): FlowDetailSheet = FlowDetailSheet().apply {
            arguments = Bundle().apply { putString(ARG_ID, flowId) }
        }
    }
}
