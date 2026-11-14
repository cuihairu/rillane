# 可选 Mesh 使用参考

Mesh 面向自己管理的 client/relay/exit 节点，与普通订阅代理是两条不同的装配路径。[v1 架构](design/architecture-v1.md)将 Mesh 保持为可选能力；节点能代理流量不代表它理解 Rillane Mesh。

## 现有入口

| 操作 | 接口/命令 |
|---|---|
| 节点与拓扑 | `rillanectl nodes`；`GET /nodes` |
| 链路预检与管理 | `rillanectl chain --help`；`chain dry-run`、`chain create` |
| 切换记录 | `rillanectl switches`；`GET /mesh/switches` |
| 证书工具 | `rillanectl mtls --help` |
| 撤销状态 | `rillanectl mtls revoke status`；`GET /mtls/revoked` |

完整参数与端点见 [CLI 参考](cli.md)，配置见 [配置参考](config.md)。Mesh dry-run 是受管拓扑预检，不是 v1 的通用规则 Explain，也不能展示第三方机场内部路径。

## 安全与数据面

TCP 多跳通过版本化 MeshEnvelope 描述链路，默认要求逐跳 mTLS。逐跳加密不等于端到端多跳认证。证书信任、节点身份和撤销载体由部署者管理；文件撤销状态不等于在线 CA/OCSP 查询。

UDP 有 envelope、会话映射与防重放状态，但缺少完整安全承载的部署组合仍拒绝构建。不能以开发明文开关作为生产交付，也不能把序号窗口当成消息认证。

包长、timing/shaping 与 WASM 中间件需要显式配置，且不自动提高延迟/吞吐。v1 的 small/mobile 构建会进一步裁剪这些依赖；当前 runtime 仍经 plugins 带入 Wasmtime。

## 观测口径

`/metrics` 和组/切换接口能说明已记录的质量与状态，不等于完整逐连接轨迹。当前部分名为 loss 的数据实际是连接错误率，不能视为游戏包丢失率。v1 将质量类型、来源、时效与样本数量分开，详见 [Debug 与 MCP](design/debug-and-mcp.md)。

链路健康变化、配置更新和故障回退不能承诺现存 TCP/UDP 无损换出口；目标地址/源映射变化可能需要应用重连。普通订阅兼容、三桌面分流与基础六平台支持不等待可选 Mesh 增强。
