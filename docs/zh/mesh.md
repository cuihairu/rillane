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

包长、timing/shaping 与 WASM 中间件需要显式配置，且不自动提高延迟/吞吐。构建档位已可裁剪：runtime 的 `plugins` feature（default=`full`）携带 Wasmtime；`small`/`mobile` 档（`--no-default-features --features small`）依赖图无 Wasmtime，`obfuscation.plugins` 声明在配置校验期以稳定原因码 `config.combo.unsupported` 点名拒绝——内置 padding/timing/shaping 链与标准订阅照常工作。

## 观测口径

`/metrics` 和组/切换接口能说明已记录的质量与状态，不等于完整逐连接轨迹。当前部分名为 loss 的数据实际是连接错误率，不能视为游戏包丢失率。v1 将质量类型、来源、时效与样本数量分开，详见 [Debug 与 MCP](design/debug-and-mcp.md)。

链路健康变化、配置更新和故障回退不能承诺现存 TCP/UDP 无损换出口；目标地址/源映射变化可能需要应用重连。普通订阅兼容、三桌面分流与基础六平台支持不等待可选 Mesh 增强。

## 受管能力协商（RIL-050）

能力交换是受管信道合约（`crates/rillane-mesh/src/negotiation.rs`）：

- **信任优先**：只有经认证（mTLS 绑定身份）信道上的声明才参与协商；
  匿名 hello 一律拒绝（稳定原因码 `mesh.cap.untrusted`）——协商面绝不
  把「缺失的声明」当「具备的能力」。（发送侧连通性兜底——无法确认对端
  版本时不填充——与此正交：那是流量面的容忍，不是协商面。）
- **版本交集**：数据面帧版本取双方申报版本集交集的最大公共版本；无交
  集以 `mesh.cap.incompatible` 拒绝并点名两侧版本集。
- **显式保守，绝不 fail-open**：能力逐字段判定——单侧缺填充声明即关闭
  填充并在协商说明里点名缺失方向；任一侧 UDP 安全承载未完成即拒绝
  UDP mesh 并把原因写进协商结果。回退全部可审计，绝不静默降级。

## 标准代理独立性与明文门

订阅产物的运行时在 mesh/chain 关闭（默认 false）时不携带任何 mesh 面：
无注册表、无 UDP 面——装配面如实缺席，不是「开着空转」。验收：
`crates/rillane-runtime/tests/optional_extension_assembly.rs` 在全部扩展
关闭下真实转发。

UDP mesh 明文门默认拒绝：无 TLS 且未显式允许明文 → 拒绝启动并点名明
文；配置 TLS 后同一门放行。显式明文开关是开发面
（`RILLANE_MESH_UDP_ALLOW_PLAINTEXT` / 配置等价物）——永非默认，也永不
是生产交付路径。

插件与策略面隔离：携带真实 Wasm 插件的运行时与同构无插件运行时路由决
策逐流一致；插件只做字节层工作——不改向、不拦截标准转发。
