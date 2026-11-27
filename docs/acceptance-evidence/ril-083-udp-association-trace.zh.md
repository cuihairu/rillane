# RIL-083 — UDP 关联与探测流轨迹接线（本地可核验段，2026-11-27）

## 交付内容

第二段的具名缺口就此收口：UDP 关联流与 url-test 探测流现在把真实诊断
轨迹写进同一个共享 `FlowCollector`，`/trace/*` 覆盖剩下的全部内核可见
来源。

**UDP 关联面**——接线在会话表本体（`crates/rillane-core/src/udp/
trace.rs`，表方法 `attach_trace_wiring`，由 `Runtime::start()` 与 TCP 面
`TracedFlowOutput` 同点调用；表构造期采集器尚不存在，走
`attach_chain_events` 同先例）。UDP 不走 TCP 的 `FlowOutput` 链（独立
泵，relay-path §4），轨迹事件落在会话表的真实生命周期点上：

- **takeover**（`session.takeover`）——容量门后会话创建，detail 携消毒
  后的 `association client <addr> [user <name>]`。
- **rule**（`route.rule`，预测证据）+ **plan**（`route.plan`，预测证
  据）——每次粘滞决策产出（含重路由——重路由是真实事件）；决策带原因
  才发 `rule`。
- **association.mapped**（观测证据）——映射绑定（节点取决策路径；
  Reused 复用不重发）。
- **association.reclaimed**（观测证据）——`force_revoke` 显式吊销
  （SOCKS5 控制链 EOF、协议 UDP 面会话收口、管理吊销共用）。
- **association.closed**（观测证据）——空闲/寿命扫描回收（detail 携
  原因）。

共用会话表的各起源协议（SOCKS5 UDP、vless/vmess/trojan/hysteria UDP
面）同批获得同一套生命周期事件。

**url-test 探测面**——探测 handler 把节点的已装配出口输出包一层
`TracedFlowOutput`（runtime_builder 探测 handler）。探测是走真实
forward 路径的合成 duplex 流，因此按 `origin=stream` 落轨：takeover →
rule（`url-test probe`）→ plan → close；轨迹终态以转发真实完成为准，
不按探测返回值造数（超时探测的 forward 任务随后自行收口，终态如实）。

## 活面证据

`crates/rillane-ffi/tests/contract_query_face.rs` 在活 runtime 面取证中
加入真实 SOCKS5 UDP ASSOCIATE 往返（方法协商 → ASSOCIATE → SOCKS5-UDP
数据报 → 本机 UDP echo → 控制链 EOF），随后要求活采集器给出：

- 一条 `flows_item` 形条目：`origin=association`、`state=closed`、
  `last_code=association.reclaimed`、`generation=local`、≥4 事件；
- 经 `flow_found` 取详情：首事件 `session.takeover`、
  `association.mapped` 事件在场、无 `transfer.*` 事件（首字节未逐包
  测量——不造数）。

`crates/rillane-core/tests/udp_associate.rs` 新增两个确定性测试：真实
往返断言四个生命周期落点并过 `FlowTrace::validate`（序号连续/时间单调）；
`MockClock` 拨过空闲上限断言 `association.closed` 终码（与 `reclaimed`
分立）。

`contracts/schema_v1/ffi_face_v1.json`：`flows_item`/`flow_found` 注记
中陈旧的「UDP 关联面归后续批次」改为第四段事实。键集未动——schema_v1
冻结形未破。

## 诚实边界

- 首字节/逐包事件仍不产：UDP 泵未逐包测量（与 TCP 面同一不造数规则）。
- `attach_trace_wiring` 装配前诞生的会话无轨迹；生产装配序 attach 先于
  任何流量，且不做回填。
- 探测轨迹进共享有界环；url-test 大机队可挤出更旧条目（挤出计数在采集
  器统计可见——有界诊断语义不变）。
- 路由拒绝会话（容量门、表关停）无轨迹；`rule` 需要决策原因——没有就
  不发明。
- 真机验收（Android/iOS 宿主，RIL-043/094）不变；本段只是本地可核验
  面，RIL-083 主勾选保持关闭。
