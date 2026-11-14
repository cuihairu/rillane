# G1-6 设计：REALITY + XTLS-Vision 出站

> 状态：**M1 已落地（捕获 + 导入期拒绝，2026-11-10）· M1.5 已落地（配置保留 + 拨号期点名门，2026-11-10）** · M2–M4 受阻（§5）· 对应 [todo.md](../../../todo.md) G1-6 · 关联：[tls-fingerprint.md](tls-fingerprint.md)（ClientHello 组装器决策空间）· [udp-relay-path.md](udp-relay-path.md)（出站能力表）

## 执行摘要

主流商业订阅普遍携带 `reality-opts`（REALITY）与 `flow: xtls-rprx-vision`（XTLS-Vision）的 VLESS 节点。Rillane 的节点模型此前没有这两个键的字段，serde 静默丢弃后节点降级为普通 TLS VLESS：对 REALITY 服务端，非 REALITY 握手会拿到伪装站点（流量不走向代理，且任何环节都无报错）；对 Vision 服务端，连接直接失败（服务端期望 Vision 分帧）。两种结局都无声无息、无法排查——比一次响亮的导入失败更糟。

M1 落地捕获 + 导入期拒绝；**M1.5（同日）拍板翻转策略**：三个导入面捕获的字段保留进 `EgressConfig::Vless`（serde 不再静默丢键），拒绝点移到**拨号期**——`VlessConnector::gate_reality_and_flow` 在任何网络 I/O 前点名 REALITY/Vision。理由：节点级失败优于导入级失败（一个 REALITY 节点不应拖垮整份批量订阅；url-test 探活标不健康，其余节点照常工作），响亮的拨号期报错同样防住了 M1 要防的静默降级。完整 REALITY 出站承载（M2）仍受阻于 rustls 不提供 ClientHello 字节级控制（§4.3），且需要真实 xray REALITY 节点做互操作验收；Vision（M3）还需实现 Vision 分帧并做同样的真机验收。

## 1. 行为矩阵

| 节点携带 | 之前 | 之后（M1.5，现行） |
|---|---|---|
| `reality-opts`（Clash YAML / Rillane DSL） | 键被静默丢弃 → 普通 TLS VLESS → 服务端回落伪装站点，无报错 | 字段解析保留进 `EgressConfig::Vless.reality`；拨号期在任何 I/O 前点名 REALITY 的 `Err` |
| `pbk`/`sid`/`security=reality`（vless:// 链接） | 参数被静默丢弃 → 同样静默降级 | 链接捕获随节点保留，照常导入；拨号期点名 `Err`（TCP + UDP `associate`） |
| `flow: xtls-rprx-vision` | 键被静默丢弃 → 普通 VLESS → 服务端期望 Vision 分帧，连接失败 | 保留进 `EgressConfig::Vless.flow`；拨号期点名 flow 值的 `Err` |
| 两者皆无 | 普通 VLESS（不变） | 普通 VLESS（不变） |

（M1 的导入期拒绝已被取代——为什么见执行摘要。`reality-opts` 缺 `public-key` 仍在转换期响亮报错：半配置的 REALITY 绝不被静默改造成别的东西。）

错误策略（M1.5）：

- **导入期**：键被捕获、绝不丢弃；仅不完整的 REALITY 块（缺 `public-key`）报错并点名节点。
- **拨号期**（TCP `forward` 与 UDP `associate`）：REALITY/flow 节点自身连接以点名错误失败，说明为何拒绝静默降级——在任何网络 I/O 之前。订阅其余节点照常工作；url-test 探活把该节点标为不健康。

## 2. 已落地实施面（M1）

- `crates/rillane-subscription/src/clash.rs` — `ClashProxy` 新增 `flow: Option<String>` 与 `reality_opts: Option<serde_yaml::Value>`（别名 `reality-opts` / `reality_opts`）；VLESS 转换臂点名拒绝。
- `crates/rillane-subscription/src/rillane_dsl.rs` — `RillaneNode` 新增 `flow` / `reality`（别名 `reality-opts` / `reality_opts`）；VLESS 臂同样拒绝。
- `crates/rillane-subscription/src/converter.rs` — `parse_vless` 捕获 `pbk`（public-key）、`sid`（short-id）、`security=reality` 进 `reality_opts`，`flow` 进 `flow`；批量导入照常保留。
- 测试：serde 捕获证明（kebab + snake 别名）、链接参数捕获、批量导入保留 REALITY 行。

### 2.1 已落地实施面（M1.5，拨号期门）

- `crates/rillane-config/src/lib.rs` — `RealityConfig { public_key, short_id }`（内层键 kebab 别名）+ `EgressConfig::Vless.reality: Option<RealityConfig>`；`flow` 已携带。
- `crates/rillane-subscription` — Clash/DSL/vless:// 三面 REALITY 节点转换成功且字段保留；仅缺 `public-key` 报错。
- `crates/rillane-protocols/src/outbound/vless.rs` — `gate_reality_flow` 在 `forward_pooled`/`forward_inline` 顶部与 `VlessUdpConnector::associate` 触发，先于任何网络 I/O。
- `crates/rillane-runtime/src/runtime_builder.rs` — 构建不再拒绝 flow/reality（构建期拒绝已移除；两臂把 `reality` 传入连接器）；clash 导出往返 `reality-opts`。
- 测试：`build_egress_outputs_carries_vless_flow_and_reality`（runtime）、`forward_rejects_reality_named_before_io` / `forward_rejects_flow_named_before_io` / `udp_associate_rejects_reality_named`（protocols）、保留式转换（clash + dsl）、`test_v2ray_bulk_import_preserves_reality_line`（converter）、`reality_config.rs`（config serde 往返）。

## 3. 协议分析

### 3.1 REALITY 握手（客户端视角）

REALITY（XTLS/Xray-core）是 TLS 1.3 伪装方案：

1. 客户端拨号服务端端口，发送以伪装站点为 SNI 的**伪造 ClientHello**；扩展顺序/密码套件模仿真实浏览器（指纹模仿——与 [tls-fingerprint.md](tls-fingerprint.md) 同一决策空间）。
2. `ClientHello.session_id`（32 B）承载认证材料：配置的 `short-id` 加上对 ClientHello 主体的截断 HMAC，密钥由 X25519 共享秘密 `x25519(client_ephemeral, server public-key)` 与时间窗派生（服务端容忍有限时钟偏移）。服务端因此在**握手完成前**即可区分 REALITY 客户端与普通访客。
3. REALITY 客户端拿到以伪装站点 SNI 生成证书链的真 TLS 1.3 握手；普通访客拿到同样的握手，随后被反代到真伪装站点。这正是 §1 所述：不知情的客户端用普通 TLS 拨 REALITY 服务端时的静默回落。
4. 握手完成后 TLS 会话承载数据通道（内部为 VLESS 风格分帧）。

### 3.2 XTLS-Vision（`flow = xtls-rprx-vision`）

Vision 消除 TLS-in-TLS 双重加密。在设置 `flow` 的标准 VLESS 请求上，双方在 VLESS 应答后切换到 Vision 分帧：先发一个填充帧，随后——当内层流量本身是 TLS 时——内层 TLS 记录原样直传（direct copy），否则按普通 VLESS 流继续。客户端从本地 TLS 客户端的明文输出读取内层 TLS 记录边界并逐记录不透明地转发；从不解密内层 TLS。

### 3.3 M2 为何受阻（栈约束）

rustls 不提供 ClientHello 字节级控制：`session_id` 内容、扩展顺序、密码套件列表均由内部生成。REALITY 第 2 步要求把认证材料写进 `session_id` 并对整个 hello 做指纹——Rust 生态没有维护中的 uTLS 等价物。候选路线（与 tls-fingerprint.md §9 同一决策空间）：

- **(a) 为 REALITY 拨号单独手写最小 TLS 1.3 客户端握手**（密钥调度 + AEAD 记录层）：体量大、安全敏感；
- **(b) 内嵌/分叉 BoringSSL 级栈**：打包成本高，破坏当前 rustls-only 依赖形态；
- **(c) rustls 分叉/shim 加 hello 组装器**：随 rustls 升级易碎。

任何一条都需要用户层面的栈决策，且没有真实 xray REALITY 服务端节点（地址、`public-key`、`short-id`、伪装 SNI）都无法做验收。

## 4. 里程碑

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M1 | 三个导入面捕获 `reality-opts`/`flow` + 导入期显式拒绝/警告 + 测试 | **已落地（2026-11-10）** |
| M1.5 | 捕获配置保留进 `EgressConfig::Vless`；拒绝点移至拨号期（TCP + UDP），任何 I/O 前点名 REALITY/Vision；clash 导出往返 `reality-opts` | **已落地（2026-11-10）** |
| M2 | REALITY 出站承载（拨号级） | BLOCKED：ClientHello 控制路线需栈层决策（§4.3）；需真实 xray REALITY 节点做互操作验收 |
| M3 | VLESS 出站上的 Vision `flow` 支持 | BLOCKED：依赖 M2 承载形态；需真实 Vision 节点；先做 loopback 向量（VMess xray 向量先例） |
| M4 | 两者真机验收 | BLOCKED：外部节点凭据 |

## 5. 验收映射

- M1：`cargo test -p rillane-subscription` — `test_vless_reality_and_flow_nodes_preserved_on_convert`（clash + dsl 两处，M1.5 翻转）、`test_rillane_node_captures_reality_and_flow_keys`、`test_vless_reality_link_params_captured`、`test_v2ray_bulk_import_preserves_reality_line`（M1.5 翻转）。
- M1.5：`cargo test -p rillane-config --test reality_config`（serde 不丢键 + 往返）、`cargo test -p rillane-protocols` 拨号门测试（TCP + UDP 点名报错）、`build_egress_outputs_carries_vless_flow_and_reality`（runtime 构建保留两字段）。
- M2–M4：仅能真机互操作验收（开启 REALITY 的 xray/sing-box 服务端），承载落地后按 tls-fingerprint.md 的可区分性测试手法补 ClientHello 捕获断言。
