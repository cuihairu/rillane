# G1-6 设计：REALITY + XTLS-Vision 出站

> 状态：**M1 已落地（捕获 + 导入期显式拒绝，2026-11-10）** · M2–M4 受阻（§5）· 对应 [todo.md](../../../todo.md) G1-6 · 关联：[tls-fingerprint.md](tls-fingerprint.md)（ClientHello 组装器决策空间）· [udp-relay-path.md](udp-relay-path.md)（出站能力表）

## 执行摘要

主流商业订阅普遍携带 `reality-opts`（REALITY）与 `flow: xtls-rprx-vision`（XTLS-Vision）的 VLESS 节点。Seep 的节点模型此前没有这两个键的字段，serde 静默丢弃后节点降级为普通 TLS VLESS：对 REALITY 服务端，非 REALITY 握手会拿到伪装站点（流量不走向代理，且任何环节都无报错）；对 Vision 服务端，连接直接失败（服务端期望 Vision 分帧）。两种结局都无声无息、无法排查——比一次响亮的导入失败更糟。

本批落地 **M1**：三个导入面全部捕获这两个键到显式字段，并在导入期点名拒绝该节点——与 plugin 无换算表的拒绝同口径。完整 REALITY 出站承载（M2）受阻于 rustls 不提供 ClientHello 字节级控制（§4.3），且需要真实 xray REALITY 节点做互操作验收；Vision（M3）还需实现 Vision 分帧并做同样的真机验收。

## 1. 行为矩阵

| 节点携带 | 之前 | 之后（M1） |
|---|---|---|
| `reality-opts`（Clash YAML / Seep DSL） | 键被静默丢弃 → 普通 TLS VLESS → 服务端回落伪装站点，无报错 | 导入期 `Err` 点名节点与 REALITY（G1-6） |
| `pbk`/`sid`/`security=reality`（vless:// 链接） | 参数被静默丢弃 → 同样静默降级 | 链接捕获 → 按批量路径约定 warning + 跳过该节点 |
| `flow: xtls-rprx-vision` | 键被静默丢弃 → 普通 VLESS → 服务端期望 Vision 分帧，连接失败 | 导入期拒绝并点名 flow 值（YAML/DSL）；链接路径 warning + 跳过 |
| 两者皆无 | 普通 VLESS（不变） | 普通 VLESS（不变） |

错误策略分面（与各面既有约定一致）：

- **Clash YAML / Seep DSL**（整份配置文件）：转换器硬 `Err`——一个坏节点在导入面即暴露，与「VLESS 缺少 UUID」硬失败一致。
- **vless:// 批量链接**：该节点被丢弃并在 `ConversionResult.warnings` 记录警告——与 `convert_v2ray` 逐行警告约定一致，其余行照常导入。门禁放在 `convert_v2ray` 链接解析之后：默认 url-test 组引用全部已解析节点，迟到的拒绝会让整个订阅导入失败。

## 2. 已落地实施面（M1）

- `crates/seep-subscription/src/clash.rs` — `ClashProxy` 新增 `flow: Option<String>` 与 `reality_opts: Option<serde_yaml::Value>`（别名 `reality-opts` / `reality_opts`）；VLESS 转换臂点名拒绝。
- `crates/seep-subscription/src/seep_dsl.rs` — `SeepNode` 新增 `flow` / `reality`（别名 `reality-opts` / `reality_opts`）；VLESS 臂同样拒绝。
- `crates/seep-subscription/src/converter.rs` — `parse_vless` 捕获 `pbk`（public-key）、`sid`（short-id）、`security=reality` 进 `reality_opts`，`flow` 进 `flow`；`convert_v2ray` 把捕获命中的节点转为 warning + 跳过。
- 测试：两个转换器的拒绝路径（普通 VLESS 不受影响）、serde 捕获证明（kebab + snake 别名）、链接参数捕获、批量导入 warning + 跳过。

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
| M2 | REALITY 出站承载（拨号级） | BLOCKED：ClientHello 控制路线需栈层决策（§4.3）；需真实 xray REALITY 节点做互操作验收 |
| M3 | VLESS 出站上的 Vision `flow` 支持 | BLOCKED：依赖 M2 承载形态；需真实 Vision 节点；先做 loopback 向量（VMess xray 向量先例） |
| M4 | 两者真机验收 | BLOCKED：外部节点凭据 |

## 5. 验收映射

- M1：`cargo test -p seep-subscription` — `test_vless_reality_and_flow_nodes_rejected_on_convert`（clash + dsl 两处）、`test_seep_node_captures_reality_and_flow_keys`、`test_vless_reality_link_params_captured`、`test_v2ray_bulk_import_warns_and_skips_reality_line`。
- M2–M4：仅能真机互操作验收（开启 REALITY 的 xray/sing-box 服务端），承载落地后按 tls-fingerprint.md 的可区分性测试手法补 ClientHello 捕获断言。
