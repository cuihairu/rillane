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
import org.json.JSONArray
import org.json.JSONObject

/**
 * 节点 Tab（RIL-150）：nodes_json 的组/成员/出口/订阅四段。
 * 空态如实：无组「未配置分组」、无出口「无出口节点」、无订阅「无订阅源」——
 * 空列表不冒充加载中。
 */
class NodesFragment : Fragment() {
    private var list: RecyclerView? = null
    private var empty: TextView? = null
    private val adapter = NodesAdapter()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View? {
        val root = inflater.inflate(R.layout.fragment_nodes, container, false)
        list = root.findViewById(R.id.nodes_list)
        empty = root.findViewById(R.id.nodes_empty)
        list?.layoutManager = LinearLayoutManager(context)
        list?.adapter = adapter
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
    }

    private fun refresh() {
        val h = RillaneVpnService.ffiHandle
        val raw = if (h != 0L) {
            try {
                RillaneFfi.nodesJson(h)
            } catch (t: Throwable) {
                null
            }
        } else null
        val rows = raw?.let { parseRows(it) } ?: emptyList()
        adapter.submit(rows)
        empty?.isVisible = rows.isEmpty()
        list?.isVisible = rows.isNotEmpty()
        if (rows.isEmpty()) {
            empty?.text = getString(R.string.nodes_no_groups)
        }
    }

    /** nodes_json → 展平行（组头/成员/出口段/订阅段） */
    private fun parseRows(raw: String): List<NodeRow> {
        val rows = mutableListOf<NodeRow>()
        val o = try {
            JSONObject(raw)
        } catch (t: Throwable) {
            return rows
        }
        val groups = o.optJSONArray("groups") ?: JSONArray()
        for (i in 0 until groups.length()) {
            val g = groups.optJSONObject(i) ?: continue
            val selected = g.optString("selected", "")
            rows.add(
                NodeRow.Header(
                    name = g.optString("name", "?"),
                    meta = buildString {
                        append("策略 ").append(g.optString("strategy", "未知"))
                        if (selected.isNotEmpty()) append("　").append(getString(R.string.nodes_selected)).append(": ").append(selected)
                    },
                ),
            )
            val members = g.optJSONArray("members") ?: JSONArray()
            for (j in 0 until members.length()) {
                val m = members.optJSONObject(j) ?: continue
                rows.add(NodeRow.Member(
                    name = m.optString("name", "?"),
                    meta = memberMeta(m),
                    status = if (m.optBoolean("healthy", false)) {
                        getString(R.string.nodes_healthy)
                    } else {
                        getString(R.string.nodes_unhealthy)
                    },
                    healthy = m.optBoolean("healthy", false),
                ))
            }
        }

        rows.add(NodeRow.Header(name = "出口节点", meta = ""))
        val egress = o.optJSONArray("egress") ?: JSONArray()
        if (egress.length() == 0) {
            rows.add(NodeRow.Plain(name = getString(R.string.nodes_no_egress), meta = "", status = ""))
        }
        for (i in 0 until egress.length()) {
            val e = egress.optJSONObject(i) ?: continue
            rows.add(NodeRow.Plain(
                name = e.optString("name", "?"),
                meta = e.optString("type", "未知"),
                status = "出口",
            ))
        }

        rows.add(NodeRow.Header(name = "订阅源", meta = ""))
        val subs = o.optJSONArray("subscriptions") ?: JSONArray()
        if (subs.length() == 0) {
            rows.add(NodeRow.Plain(name = getString(R.string.nodes_no_subs), meta = "", status = ""))
        }
        for (i in 0 until subs.length()) {
            val s = subs.optJSONObject(i) ?: continue
            val type = s.optString("type", "")
            rows.add(NodeRow.Plain(
                name = s.optString("name", "?"),
                meta = if (type.isNullOrEmpty()) "自动检测" else type,
                status = if (s.optBoolean("enabled", false)) "启用" else "停用",
            ))
        }
        return rows
    }

    private fun memberMeta(m: JSONObject): String = buildString {
        append(getString(R.string.nodes_p95)).append(" ")
        if (m.isNull("p95_ms")) append("未知") else append(m.optLong("p95_ms")).append("ms")
        append("　").append(getString(R.string.nodes_loss)).append(" ")
        if (m.isNull("loss_ratio")) append("未知") else append("%.1f%%".format(m.optDouble("loss_ratio") * 100))
    }
}

/** 展平行模型（Header = 组头/段标题；Member = 组成员；Plain = 出口/订阅行） */
sealed interface NodeRow {
    data class Header(val name: String, val meta: String) : NodeRow
    data class Member(
        val name: String,
        val meta: String,
        val status: String,
        val healthy: Boolean,
    ) : NodeRow
    data class Plain(val name: String, val meta: String, val status: String) : NodeRow
}

class NodesAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
    private val rows = mutableListOf<NodeRow>()

    fun submit(newRows: List<NodeRow>) {
        rows.clear()
        rows.addAll(newRows)
        notifyDataSetChanged()
    }

    override fun getItemViewType(position: Int): Int = when (rows[position]) {
        is NodeRow.Header -> TYPE_HEADER
        else -> TYPE_ROW
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return if (viewType == TYPE_HEADER) {
            HeaderHolder(inflater.inflate(R.layout.item_group_header, parent, false))
        } else {
            RowHolder(inflater.inflate(R.layout.item_node_member, parent, false))
        }
    }

    override fun getItemCount(): Int = rows.size

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val row = rows[position]) {
            is NodeRow.Header -> (holder as HeaderHolder).bind(row)
            is NodeRow.Member -> (holder as RowHolder).bind(row.name, row.meta, row.status)
            is NodeRow.Plain -> (holder as RowHolder).bind(row.name, row.meta, row.status)
        }
    }

    class HeaderHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val name = view.findViewById<TextView>(R.id.group_name)
        private val meta = view.findViewById<TextView>(R.id.group_strategy)
        fun bind(row: NodeRow.Header) {
            name.text = row.name
            meta.isVisible = row.meta.isNotEmpty()
            meta.text = row.meta
        }
    }

    class RowHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val name = view.findViewById<TextView>(R.id.member_name)
        private val meta = view.findViewById<TextView>(R.id.member_meta)
        private val status = view.findViewById<TextView>(R.id.member_status)
        fun bind(nameText: String, metaText: String, statusText: String) {
            name.text = nameText
            meta.isVisible = metaText.isNotEmpty()
            meta.text = metaText
            status.isVisible = statusText.isNotEmpty()
            // 健康/异常以文字表达（不单靠颜色）
            status.text = statusText
        }
    }

    companion object {
        private const val TYPE_HEADER = 0
        private const val TYPE_ROW = 1
    }
}
