# schema_v1 契约样本库（RIL-083）

跨语言线格式的**冻结样本**：IR / 诊断事件 / 控制面 DTO / FFI 查询 / MCP 工具
目录五类面的 shape 常量钉在这里，被各 crate 的 contract 测试在 CI 里逐面断言。
本目录是「兼容样本」的真源——任何一面漂移，CI 以具名 diff 失败（缺键 / 多键 /
类型漂移逐一点名），破坏兼容的变化**明确失败**而不是静默扩散到移动端 / MCP
消费者。

## 面与门

| 样本文件 | 钉住的面 | 测试门 |
|---|---|---|
| `ir_face_v1.json` | rillane-config IR 投影（**subset 面**：必需键 + 类型；新增可选字段不算破坏） | `crates/rillane-config/tests/contract_ir_sample.rs` |
| `trace_face_v1.json` | 诊断事件冻结形（schema_version=1：trace/event/collector 九计数） | `crates/rillane-core/tests/contract_trace_face.rs` |
| `control_face_v1.json` | rillaned 控制面 DTO（/runtime/stats、/dns/stats、/dns/resolvers） | `apps/rillaned/src/control_plane.rs`（内联测试） |
| `ffi_face_v1.json` | rillane-ffi 查询面（stats/routing/nodes/dns×2/flows/flow + 错误信封）与 C 头文件↔导出符号集 | `crates/rillane-ffi/tests/contract_query_face.rs` |
| `mcp_tools_face_v1.json` | MCP 工具目录冻结契约（16 工具 name/title/description/scope/注解/输入输出 schema） | `crates/rillane-app/tests/contract_tools_face.rs` |

## 两种钉法

- **subset 面**（`ir_face_v1.json`）：只断言「必需键存在且类型相符」，
  实际面**多出**键不失败——配置 IR 允许增量演进（新可选块零差异纪律）。
- **exact 面**（其余全部）：实际键集**恰等于**声明键集——这些是
  schema_version=1 冻结线格式，移动端脚本 / MCP 客户端按字段名消费，
  加键减键都要求显式过门（本文件更新 + 具名理由），不静默通过。

## 同版本一致解释

`schema_version` 在控制面信封（`json_v1` / reply）、FFI 查询、MCP
structuredContent 三处各自落地为 `1`；本库的 exact 面把每处的
`schema_version` 键一并钉死——单面私自升版即刻失败。真正的跨面升级
= 整目录复制为 `schema_v2/` 并在**同一提交**里更新全部五门 + 各面
具名变更理由（升级是仓库级事务，不是单面局部改动）。

## 已记录的跨面事实（非缺陷，如实对账）

- `/runtime/stats`（控制面 RuntimeStatsDto，12 键）与 FFI
  `stats_json`（9 键）**不是全等面**：控制面多 mesh_nodes /
  mesh_sessions / network_interfaces / subscription_nodes /
  last_updated_ago_seconds，FFI 多 is_running / tun_fd。两者在
  `shared_stats_subset`（7 键）意义上同形——该子集被两面同时钉死，
  任一面收窄子集即失败。
- MCP `probe_submit` 输入 schema 携带 `oneOf` 联合（合法 JSON
  Schema）——官方 ListToolsResultSchema 校验器拒绝该形（RIL-090
  边界如实记录），本快照按服务端真实形态冻结，不为过官方校验器
  而改形。

## 边界（如实）

- 移动 FFI 增量（RIL-043 批次的批次缓冲 / ABI 版本面）落地下
  在此追加 `ffi_face_v1.json` 新面并留具名理由——本版不含未落地
  面的占位。
- MCP 协议层（握手 / 信封 / 错误码）行为面由 sdk-acceptance
  驱动（apps/rillane-mcp）+ rillane-app mcp.rs 常量钉住；本库只钉
  **工具目录快照**，不重复钉协议层。
- i18n：description/title 文本属冻结契约的一部分（客户端可能直显），
  改文案即过门。
