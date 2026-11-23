# rillane-mcp SDK 互操作验收（RIL-090）

固定官方 SDK 的**真实客户端**对 `apps/rillane-mcp` stdio 适配器的互操作
验收驱动：官方 `StdioClientTransport`（子进程 + stdio 帧）+ 官方
`Protocol`（请求/答复/取消管理），全程零模型（驱动是脚本，不是 LLM）。

- 固定 SDK：`@modelcontextprotocol/sdk@1.32.2`（官方，2026-10-23 发布体）。
- 服务端契约：冻结 modern era `2026-07-28`（RIL-066——无 initialize
  握手，逐请求 `params._meta["io.modelcontextprotocol/protocolVersion"]`
  声明版本）。
- 证据与边界发现：见 [EVIDENCE.md](EVIDENCE.md)。

## 运行

```sh
# 1) 构建三件套（可用 CARGO_TARGET_DIR 指向私有 target）
cargo build -p rillane-mcp -p rillaned -p rillanectl

# 2) 安装固定依赖（node_modules 已被 .gitignore 覆盖）
npm install

# 3) 跑验收（12 场景；退出码 0 = 全通过）
CARGO_TARGET_DIR=<你的 target> node accept.cjs   # 或 npm run accept
```

前置 Node ≥ 22（开发席位以 v24 验证）。守护进程以临时目录 + 动态空闲
端口自举（含 `RILLANE_MESH_ALLOW_PLAINTEXT=1` 开发环境明文放行门——
验收守护仅服务控制面，无 mesh 对端），不触碰 9090 等既有实例。

二进制路径可用 `RILLANE_MCP_BIN` / `RILLANE_DAEMON_BIN` /
`RILLANE_CTL_BIN` 覆盖（缺省取 `CARGO_TARGET_DIR` 或仓根 `target/` 的
`debug/`）。

## 场景（12）

| # | 场景 | 验证点 |
|---|---|---|
| 1 | server/discover | 官方 SDK 请求探测面；supportedVersions/capabilities/`_meta` serverInfo |
| 2 | tools/list | 16 工具目录；无 nextCursor → 分页循环正确终止；目录不泄漏 scope；官方 schema 校验（记录性） |
| 3 | 读工具闭环 | runtime_stats/flow_list/routing_quality/config_audit 对活守护进程 isError=false |
| 4 | 权限拒绝 | 只读档 × apply_config_change → -32001 + `data.code=mcp.scope.denied`；拒绝不进边界 |
| 5 | 错误面 | 未知名 -32602；缺 name -32602/mcp.input.required；旧版本 -32022（supported 指引重试）；legacy initialize -32601 |
| 6 | Client.connect()（记录性） | 发布版 SDK 高层 legacy 握手与冻结 modern 面不互通的精确码 |
| 7 | 取消·AbortSignal | SDK 原生取消路径：在途请求 + notifications/cancelled |
| 8 | 取消·答复抑制 | 取消先登记 → 该请求答复不写（冻结契约）；对照请求照常 |
| 9 | 启动退出 | EOF（stdin 关闭）→ 干净退出码 0 |
| 10 | 断连恢复·守护侧 | kill → 带内 isError 稳定码信封；复活后同一 MCP 会话恢复 |
| 11 | 断连恢复·服务端侧 | SIGKILL rillane-mcp → 新会话恢复 |
| 12 | 模型缺席 | 零 LLM 下守护 + `rillanectl stats` 照常运行 |

## 已知边界（如实）

- 发布版 SDK 根入口 `dist/esm/index.js` 在 1.20.0–1.32.2 发布体中缺失
  （npm tarball 实查），须走深路径 require（`./*` 导出映射 require 条件
  → `dist/cjs/*`，带 `.js` 后缀）。
- 官方 `Protocol` 是抽象基类（`assertRequestHandlerCapability`），
  驱动以 modern era 语义将其实现为空（纯客户端无服务端→客户端请求）。
