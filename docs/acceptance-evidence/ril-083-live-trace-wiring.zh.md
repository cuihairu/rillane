# RIL-083 — SessionTracer 活面接线（本地可核验段，2026-11-26）

## 交付内容

TCP 入口流现在会把真实诊断轨迹写进共享 `FlowCollector`。生产装配点在
`crates/rillane-runtime/src/runtime_builder.rs`：每个入口挂一层
`TracedFlowOutput`（包住既有 `StatsFlowOutput`），装配点在
`Runtime::start()` 的 per-ingress spawn 处。一流一轨。

事件口径（只记内核可见事实，不造数）：

- **takeover**（`session.takeover`）——首事件兼采集器准入锚点，detail
  携消毒后的入口/协议/目标。
- **rule**（`route.rule`，预测证据）——冻结决策带原因才发；**plan**
  （`route.plan`，预测证据）——冻结决策的路径摘要。
- **close**——转发成功 `session.closed`（detail 携上行/下行字节数），
  转发失败 `session.failed`（detail 消毒）。两者都冻结轨迹并 finish
  采集器记录，终态恒可观测。

attempt 与首字节 transfer 事件有意缺席：生产泵不逐次测量拨号尝试与
分向首字节，轨迹回答「谁被接走 / 为何这么路由 / 走没走通 / 搬了多少
字节」，不假装测过没测的东西。

代际恒 `local`——流经构建期配置装配（RIL-016 来源语汇）；热更新代际
随流推进归 RIL-008 接线。detail 进轨迹前过 `sanitize_untrusted`
（RIL-057 同一消毒闸）。

## 活面证据（非 mock）

`crates/rillane-ffi/tests/contract_query_face.rs`（3/3 绿）真实启动
runtime，驱动真实 socks5 → direct → 本机 echo 的 TCP 往返，然后轮询
FFI 查询面直到轨迹到终态：

- `flows.items[*]` 非空，首项恰合冻结的 `flows_item` exact 面
  （origin `stream`、state `closed`、last_code `session.closed`、
  generation `local`、事件数 ≥3）。
- `rillane_ffi_flow_json(id)` 应答 `found:true`，恰合冻结的
  `flow_found` exact 面，`trace` 已闭合、首事件 `session.takeover`、
  事件数与列表摘要一致。
- 未知 ID 仍走稳定 `flow_absent` 形——活轨迹不改变显式缺席语义。

`contracts/schema_v1/ffi_face_v1.json` 自 schema_v1 语料落地（RIL-083
第一段）起在 `flows_item` 与 `flow_found` 标
`verification: pending_live_trace_wiring`。本段把两处标记替换为
`live_trace_wiring_ril083`，并把旧的「标记在场」断言转为「活面证据在
场、pending 标记不得回潮」——摘标记是显式过门动作。

## 诚实边界

- UDP 关联流与 url-test 探测流原为本段具名缺口；已于第四段接线
  （会话表侧 `attach_trace_wiring` 与探测 `TracedFlowOutput` 包装），
  见 [ril-083-udp-association-trace](ril-083-udp-association-trace)。
- 在 `FlowOutput.forward` 之前被拒的流（路由失败）与无原因的决策按
  设计不产 `rule` 事件；不为凑事件序列造数。
- 真机验收（Android/iOS 宿主，RIL-043/094）不变；本段只是本地可核验
  面，主勾选保持关闭。
- 交付批次全 workspace 测试、fmt、clippy -D warnings 全绿；本文记录
  的是段，不是发布。
