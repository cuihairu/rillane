package com.rillane.rillane

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.json.JSONArray
import org.json.JSONObject

/**
 * 连接 Tab（RIL-150）：flows_json(0,20) 列表 + 点开 FlowDetailSheet。
 * demo 数据面仅 ICMP → 真实空列表如实「无连接记录」（collector 已启用，
 * 非「追踪关闭」）。流 ID 查询框经 flowJson(id) 走详情路径——未知 ID →
 * found:false + query.flow.unknown + 收集器计数。
 */
class ConnectionsFragment : Fragment() {
    private var list: RecyclerView? = null
    private var empty: TextView? = null
    private var input: TextInputEditText? = null
    private val adapter = ConnectionsAdapter()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        val root = inflater.inflate(R.layout.fragment_connections, container, false)
        list = root.findViewById(R.id.connections_list)
        empty = root.findViewById(R.id.connections_empty)
        input = root.findViewById(R.id.flow_id_input)
        list?.layoutManager = LinearLayoutManager(context)
        list?.adapter = adapter

        root.findViewById<MaterialButton>(R.id.flow_query_btn)?.setOnClickListener {
            val id = input?.text?.toString()?.trim().orEmpty()
            if (id.isNotEmpty()) {
                FlowDetailSheet.newInstance(id).show(parentFragmentManager, "flow_detail")
            }
        }
        return root
    }

    override fun onStart() {
        super.onStart()
        refresh()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        list = null
        empty = null
        input = null
    }

    private fun refresh() {
        val h = RillaneVpnService.ffiHandle
        val raw = if (h != 0L) {
            try {
                RillaneFfi.flowsJson(h, 0, 20)
            } catch (t: Throwable) {
                null
            }
        } else null
        val rows = raw?.let { parseRows(it) } ?: emptyList()
        adapter.submit(rows) { flowId ->
            FlowDetailSheet.newInstance(flowId).show(parentFragmentManager, "flow_detail")
        }
        empty?.isVisible = rows.isEmpty()
        list?.isVisible = rows.isNotEmpty()
    }

    private fun parseRows(raw: String): List<FlowRow> {
        val rows = mutableListOf<FlowRow>()
        val o = try {
            JSONObject(raw)
        } catch (t: Throwable) {
            return rows
        }
        // limit=0 错误信封：error 字段在场 → 空列表（连接 Tab 如实空态）
        if (o.has("error")) return rows
        val items = o.optJSONArray("items") ?: JSONArray()
        for (i in 0 until items.length()) {
            val it = items.optJSONObject(i) ?: continue
            rows.add(
                FlowRow(
                    flow = it.optString("flow", "?"),
                    origin = it.optString("origin", "?"),
                    state = it.optString("state", "?"),
                    events = it.optLong("events", 0),
                    firstWallMs = it.optLong("first_wall_ms", 0),
                    lastCode = it.optString("last_code", ""),
                ),
            )
        }
        return rows
    }
}

/** 连接行模型 */
data class FlowRow(
    val flow: String,
    val origin: String,
    val state: String,
    val events: Long,
    val firstWallMs: Long,
    val lastCode: String,
)

class ConnectionsAdapter : RecyclerView.Adapter<ConnectionsAdapter.Holder>() {
    private val rows = mutableListOf<FlowRow>()
    private var onClick: ((String) -> Unit)? = null

    fun submit(newRows: List<FlowRow>, onRowClick: (String) -> Unit) {
        rows.clear()
        rows.addAll(newRows)
        onClick = onRowClick
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_flow, parent, false))

    override fun getItemCount(): Int = rows.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        holder.bind(rows[position])
    }

    inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
        private val name = view.findViewById<TextView>(R.id.flow_name)
        private val state = view.findViewById<TextView>(R.id.flow_state)
        private val meta = view.findViewById<TextView>(R.id.flow_meta)

        init {
            itemView.setOnClickListener {
                val row = rows.getOrNull(bindingAdapterPosition) ?: return@setOnClickListener
                onClick?.invoke(row.flow)
            }
        }

        fun bind(row: FlowRow) {
            name.text = row.flow
            state.text = row.state
            meta.text = "${row.origin} · 事件 ${row.events} · ${row.lastCode}"
        }
    }
}
