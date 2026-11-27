# RIL-083 契约与跨语言 CI — 破坏兼容 bite 矩阵（本地段，2026-11-27）

## 交付内容

验收条款「破坏兼容的变化明确失败」此前在五个冻结面门中的三个已有自证
（config IR：类型漂移 + 缺键；core trace：面滞后 + 多键；MCP 工具：两条；
FFI 查询：面滞后）。本段补齐负向方向未证处——不改任何生产代码：

- **FFI 查询门补「缺键」方向**（`crates/rillane-ffi/tests/contract_query_face.rs`
  `comparator_bites_on_dropped_key`）：实现丢一个已声明键（最坏的破坏
  兼容——消费方按字段名取数即断）必须被对账器以
  `ffi 面漂移 @ stats_json：缺键` 点名。
- **rillaned 控制面门补两向**（`apps/rillaned/src/control_plane.rs`，
  该门此前零自证）：`comparator_bites_on_dropped_key` 把**真实**
  `/runtime/stats` 投影删掉 `total_connections`、面保持冻结 →
  `控制面漂移 @ runtime_stats：缺键`；`comparator_bites_on_extra_key`
  向真实投影注入 phantom 键 → `控制面漂移 @ runtime_stats：多键`。
  两条都跑真控制面（build_runtime + handle），对账器是在生产形状上被证
  会咬，不是手捏替身。
- **跨语言结构门补版本冻结 bite**（
  `crates/rillane-platform/tests/schema_cross_language_contract.rs`）：
  schema_version 检查原是 inline assert，现提取为可调用对账器
  `assert_face_version_frozen` 供主测试使用，并加
  `comparator_bites_on_version_bump`：样本被升到 `schema_version: 2`
  （未走整目录复制事务）必须以 `版本漂移` 失败。

本段之后五个冻结面（config IR、core trace、控制面 DTO、FFI 查询、MCP
工具）加结构门，每个都至少有一条具名负向自证：面滞后于现实、键被丢/被
加、版本未走事务被升——对应门必须点名漂移，不得静默放行。

## 诚实边界

- 自证钉的是对账器在机器本地面上会咬；宿主桥接与 MCP 官方协议层对同一
  版本的解释不在内（见 `contracts/schema_v1/README.md` 边界，宿主/真机
  批次开放）。
- 自证使用注入/内存变异值，不改磁盘上的冻结面文件。
