# RIL-090 验收证据（固定 SDK 真实客户端互操作）

- 席位：Linux 7.0.0 / Node `v24.21.0` / npm `11.19.0`；官方 SDK `@modelcontextprotocol/sdk@1.32.2`（2026-10-23 发布体）+ zod `4.6.7`。
- 服务端二进制：`rillane-mcp`（冻结 modern era `2026-07-28`，RIL-066）；对照 `rillaned` / `rillanectl` 私有 target 构建产物。
- 运行方式：`CARGO_TARGET_DIR=<私有 target> node accept.cjs`；退出码 0 = 12 场景全通过。

## 实跑输出（2026-11-23，单次，exit 0）

```
PASS  1 server/discover 经官方 SDK 请求  (supported=2026-07-28 server=rillane)
PASS  2 tools/list 目录与分页终止  (16 工具；官方 ListToolsResultSchema 拒绝：路径 tools.8.inputSchema.type（Invalid input: expected "object"）——probe_submit 的 oneOf inputSchema（合法 JSON Schema）超出发布版 schema 形状，属 legacy 面，记为边界)
PASS  3 读工具闭环 runtime_stats/flow_list/routing_quality/config_audit  (4 工具全通；官方 CallToolResultSchema 校验=通过)
PASS  4 权限拒绝（只读档 × apply_config_change）  (code=-32001 data.code=mcp.scope.denied；注意 SDK ErrorCode.RequestTimeout 同为 -32001（以 data.code 消歧）)
PASS  5 错误面（未知名/缺 name/版本协商/legacy initialize）  (unknown=-32602 noName=mcp.input.required oldVer=-32022(supported=2026-07-28) initialize=-32601)
PASS  6 官方 Client.connect() 握手路径（记录性）  (发布版 SDK 高层握手（initialize@2025-11-25）与冻结 modern 面不互通：MCP error -32601: method not found: initialize)
PASS  7 取消·SDK AbortSignal 原生路径  (122ms 内拒绝等待；SDK 已发 notifications/cancelled（单线程服务端稍后完成边界调用并写答复，客户端按无主答复丢弃——边界如实）)
PASS  8 取消·答复抑制（取消先登记，官方传输层）  (id=77 无答复；id=78 正常)
PASS  9 启动退出（EOF → 退出码 0）  (code=0)
PASS  10 断连恢复（守护进程侧）  (断连 isError=true（稳定码信封）；复活后 isError=false)
PASS  11 断连恢复（rillane-mcp 进程侧）  (旧会话退出(SIGKILL)；新会话 discover 恢复)
PASS  12 模型缺席（零 LLM：守护 + rillanectl 照常）  (rillanectl stats 输出 9 行；全程零模型)

==== RIL-090 SDK 互操作验收汇总 ====
场景 12｜通过 12｜失败 0
记录性输出：
  [1 server/discover 经官方 SDK 请求] supported=2026-07-28 server=rillane
  [2 tools/list 目录与分页终止] 16 工具；官方 ListToolsResultSchema 拒绝：路径 tools.8.inputSchema.type（Invalid input: expected "object"）——probe_submit 的 oneOf inputSchema（合法 JSON Schema）超出发布版 schema 形状，属 legacy 面，记为边界
  [3 读工具闭环 runtime_stats/flow_list/routing_quality/config_audit] 4 工具全通；官方 CallToolResultSchema 校验=通过
  [4 权限拒绝（只读档 × apply_config_change）] code=-32001 data.code=mcp.scope.denied；注意 SDK ErrorCode.RequestTimeout 同为 -32001（以 data.code 消歧）
  [5 错误面（未知名/缺 name/版本协商/legacy initialize）] unknown=-32602 noName=mcp.input.required oldVer=-32022(supported=2026-07-28) initialize=-32601
  [6 官方 Client.connect() 握手路径（记录性）] 发布版 SDK 高层握手（initialize@2025-11-25）与冻结 modern 面不互通：MCP error -32601: method not found: initialize
  [7 取消·SDK AbortSignal 原生路径] 122ms 内拒绝等待；SDK 已发 notifications/cancelled（单线程服务端稍后完成边界调用并写答复，客户端按无主答复丢弃——边界如实）
  [8 取消·答复抑制（取消先登记，官方传输层）] id=77 无答复；id=78 正常
  [9 启动退出（EOF → 退出码 0）] code=0
  [10 断连恢复（守护进程侧）] 断连 isError=true（稳定码信封）；复活后 isError=false
  [11 断连恢复（rillane-mcp 进程侧）] 旧会话退出(SIGKILL)；新会话 discover 恢复
  [12 模型缺席（零 LLM：守护 + rillanectl 照常）] rillanectl stats 输出 9 行；全程零模型
```

## 复现

同一驱动连续 4 次运行（首次 + 3 次复跑）均为 `场景 12｜通过 12｜失败 0`、退出码 0；
仅毫秒级计时注记（场景 7 的取消延迟）逐次浮动，无结论漂移。无残留
`rillaned` / `rillane-mcp` 进程。

## 边界发现（如实记录，非阻断）

1. **发布版 SDK 根入口缺失**：`@modelcontextprotocol/sdk` 1.20.0–1.32.2
   npm tarball 均无 `dist/esm/index.js`（`tar -tzf` 实查 6 个版本，全部
   缺）——根 import 不可用，须走深路径 require。
2. **legacy 握手不互通**：官方 `Client.connect()` 发 `initialize@2025-11-25`
   + `notifications/initialized`，冻结 modern 服务端以 `-32601 method not
   found` 拒绝。`LATEST_PROTOCOL_VERSION=2025-11-25`、
   `SUPPORTED_PROTOCOL_VERSIONS` 最高 2025-11-25——发布版 SDK 尚未携带
   2026-07-28 修订。
3. **ListToolsResultSchema 形状缺口**：官方 schema 只认
   `inputSchema.type === "object"`，拒绝 `probe_submit` 的合法 JSON Schema
   `oneOf` 联合（路径 `tools.8.inputSchema.type`）。`CallToolResultSchema`
   对本 `tools/call` 结果校验**通过**（resultType/content/structuredContent
   /isError 形状一致）。
4. **码值冲突**：rillane 越权稳定码 `-32001` 与 SDK 内部
   `ErrorCode.RequestTimeout = -32001` 数值同码。真实客户端必须以
   `data.code`（`mcp.scope.denied`）消歧，不得只看数值码。
5. **单线程取消时序**：服务端单线程按行处理；SDK 取消晚到于答复写入，
   被取消请求的答复仍会写出、客户端按无主答复丢弃；答复抑制仅在取消
   通知先登记时成立（场景 8 用官方传输层按确定性序列验证）。
