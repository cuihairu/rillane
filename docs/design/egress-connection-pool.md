# P1-5 出站连接池 — 实现级设计

> 上游：[roadmap.md](roadmap.md) S2/S3（"出站连接池：同出口 keep-alive 复用 + TLS 会话恢复，服务于网页短连接"）· [PROTOCOLS.md](../PROTOCOLS.md) 总表与性能节（连接池未实现 → P1-5）· [positioning.md](positioning.md) §2（三场景共享数据通路，网页加速核心项）。
> 本文是落地定稿：**镜像类型与 schema、装配与热更新、控制面、状态机、测试策略、分步实施清单**。落地后偏差回填 §10。
> 复用基线：`EgressConnector` 接管式契约（`seep-core/src/lib.rs:625-628`）· `ConnectorFlowOutput` 适配层（`runtime_builder.rs:1466`）· `build_egress_outputs` 装配（`runtime_builder.rs:1635`，调用点 :158 / :720 / :933）· `RuntimeConfig.connection_pool_size`（`runtime_builder.rs:311`，缺省 `Some(1024)`，全仓零消费孤儿字段）· `tls.rs:10-47` 每流重建 `ClientConfig`（调用点 trojan.rs:101 / http.rs:92 / vless.rs:190、:228）· `perform_connect<S>` 泛型（http.rs:126）· rustls 0.23.35 公开面（`Resumption::in_memory_sessions` 为默认恢复策略、`HandshakeKind` 经 `CommonState::handshake_kind()` 可观测，源码核对见 §2.4）· `UdpConfig` 镜像 + runtime 转换先例（[udp-dataplane.md](udp-dataplane.md) §5.2）· 新块 `deny_unknown_fields` 定向收口（[network-route.md](network-route.md) §1.5）· MockClock（P0-1）· 封闭标签（R11）· 控制面 getter 模式（`control_plane.rs:23`/`:259`/`:386`）与手写 `/metrics`（`:245`）。

## 0. 范围与验收口径

### 0.1 范围

| 在本条目内 | 归其他条目 |
|-----------|-----------|
| `egress_pool:` 配置区块（seep-config 镜像类型）+ `PoolPolicy`/`TransportPool`/`TlsConnectorFactory`（seep-protocols） | 多路复用（一条连接内并发多流，含 hy2/QUIC 会话复用）= V2——总拨号数不降的结构原因见 §0.2 注记 |
| MVP 矩阵出站接入：trojan / http（含 tls）/ vless（tcp+ws，含 tls）/ direct（`pre_dial_direct` 选通） | socks5 / shadowsocks 池化 = 扩展（crate 合并拨号+绑定，D-6）；vmess = 未实现条目；wg = 系统接口无用户态拨号 |
| TLS 会话恢复（进程级共享 `ClientConfig`）+ `HandshakeKind` 观测计数 | uTLS 指纹模拟 = P2-5（`tls.rs` 同一挂点，工厂为其收敛注入面，互指 §2.4） |
| `connection_pool_size` 孤儿字段收编（全局容量缺省，D-8） | mesh hop 拨号复用（`connect_next` 每流拨号）= O 项非承诺（§11） |
| `/metrics` `seep_pool_*`/`seep_tls_*` 序列 + `GET /egress/pool/stats` + 验收统计脚本 | UDP 面 = P0-4/P0-5（无连接建立语义，零交叠 §1.3）；混淆中间件 = P1-4（Flow 级，严格上下游 §1.3） |

### 0.2 验收口径（显式）

todo P1-5 验收原文："重复请求同目标握手次数下降，`/metrics` 有连接复用率指标；现有配置无破坏性变更"。结合本条目标题口径（同出口同 SNI keep-alive 复用 + TLS 会话恢复），四条判据：

1. **同出口同 SNI keep-alive 复用（可测）**：同一 (egress, SNI) 连续 N≥10 次串行请求 → `seep_pool_acquires_total{result="hit"}` ≥ N−1（装配预热后首请求即命中，miss 可为 0）、`seep_pool_reuse_ratio` ≥ (N−1)/N；
2. **握手次数下降（口径注记，对齐 P0-3/P1-4 显式改写做法，不静默缩水）**：可测口径 = **请求路径阻塞握手次数**——命中借出的请求零拨号零握手（前台 dial 计数不增）；叠加会话恢复使预热/补充拨号的全量握手被 `HandshakeKind::Resumed` 取代（`seep_tls_handshakes_total{type}` 对比）。**总拨号次数 ≈ 流数，不降**——每个流消耗一条连接（§1.2 结构约束），真降总连接数需多路复用（V2）。验收统计脚本同时输出三组数（前台握手 / 恢复占比 / 总拨号）避免歧义；
3. **连接复用率指标**：`seep_pool_reuse_ratio`（gauge）+ `seep_pool_acquires_total{result}` 计数，`/metrics` 可见；
4. **现有配置无破坏性变更**：无 `egress_pool:` 块 → 解析与行为零差异（serde 往返 + 行为对照断言）；`connection_pool_size` 仅在块存在且未写 `max_idle_global` 时被消费（此前它零消费）。

## 1. 现状与结构约束（决策的事实输入）

### 1.1 连接建立路径现状（核对结论，非重述）

| 出站 | forward 内连接建立（落点） | 协议绑定（目标相关字节） | 传输/绑定可拆性 |
|------|--------------------------|--------------------------|----------------|
| direct | `TcpStream::connect(target)`（direct.rs） | 无（纯透传） | 目标即传输终点，键=target |
| trojan | `TcpStream::connect(server)` → `create_tls_connector`（trojan.rs:101）→ TLS connect(sni) | trojan 请求头（SHA224+CRLF+ATYP+target） | **天然可拆**：头在 TLS 建立后写入 |
| http | `TcpStream::connect(proxy)` → [TLS]（http.rs:92）→ `perform_connect` | CONNECT 请求 | **天然可拆**：`perform_connect<S>` 泛型（http.rs:126），绑定独立于传输 |
| vless | `TcpStream::connect(server)` → [TLS]（vless.rs:190 tcp / :228 ws） | vless 头（tcp 分支）/ WS upgrade+vless 头（ws 分支，host/path 由出站配置决定，目标无关） | **可拆**：两分支均为"先传输后绑定" |
| socks5 | `tokio_socks::tcp::Socks5Stream::connect(proxy, target)` | greeting+auth+CONNECT 与拨号**合并**在 crate 调用内 | 不可拆（无外部流注入口；且无 TLS 层收益低） |
| shadowsocks | `ProxyClientStream::connect(context, server_cfg, target)` | 目标地址进首写，与拨号**合并** | 不可拆（crate 公开 API 形态；实施时再核查注入口） |
| hysteria2 / wireguard | QUIC 会话 / 系统接口 | — | 非本模型（QUIC 复用归 V2 mux / 无用户态拨号） |

### 1.2 结构性约束：绑定即消费（池形态的推导前提）

- `EgressConnector::forward(Flow) -> FlowReport`（`seep-core/src/lib.rs:625-628`）为**接管式**：连接在 forward 内建立、随流终结。`copy_bidirectional` 返回 = 双向 EOF（任一侧先关，另一侧被 shutdown 写半部）——**连接终态，不可归还复用**。这不是实现缺陷而是隧道协议语义：目标连接关闭后，代理服务器随即关闭隧道连接；
- 推论：**"借出后归还"式连接池在当前架构下不可实现**（需改转发语义或 mux，均出界）。可实现的形态 = **预建立（warm）池**：预先拨好 TCP[+TLS]、**零协议字节写入**的传输层连接，按键缓存；流到来时借出（checkout），协议头在借出后写入；流结束连接消耗掉；借出触发后台水位补充；
- 收益定位（§0.2 注记的事实基础）：前台（阻塞请求路径的）握手 → 0（命中时）；TLS 会话恢复使池自身拨号的全量握手 → Resumed；**总拨号 ≈ 流数不变**。

### 1.3 三层接缝（与 P1-4 / P0-x 的边界互指）

| 层 | 条目 | 挂点 | 管什么 | 与本条目的接缝 |
|----|------|------|--------|---------------|
| Flow 级处理 | P1-4 混淆中间件 | `FlowOutputRouter::forward` ①②③（分派**前**，[obfuscation-middleware.md](obfuscation-middleware.md) §1.3） | Flow 的流字节形态（padding spec 注解 + 帧载体执行） | **严格上下游**：池在 connector.forward 内部（分派**后**，传输级）。P1-4 MVP 帧载体仅 chain `MeshEnvelope`（其 §2.3），与池零交叠；未来若出站侧填充，填充作用于借出后的流字节——池管连接生命周期、不管字节内容，正交 |
| TCP 传输 | **本条目** | `build_egress_outputs` 装配进 connector（§4） | 到出站服务器的 TCP[+TLS] 会话建立成本 | — |
| UDP 会话 | P0-1/P0-4/P0-5 | `UdpSessionTable` / `UdpEnvelope` / `seep_udp_*` | NAT 式数据报会话（粘滞/回收） | **零交叠**：UDP 无连接建立语义（无 TCP/TLS 握手可消），`EgressUdpConnector`/`RoutingUdpConnector`/`UdpSessionTable` 一概不动；三层各管一段（IP 会话 / Flow 处理 / TCP 传输） |

mesh 面：`connect_next` 每流 hop 拨号（`mesh_transport.rs:406`）本条目**不动**——mesh hop 的 `MeshEnvelope` 首写即协议绑定，形状与池兼容（键=hop 地址），未来复用记 §11 O-pool1，非承诺。

## 2. 决策（D-x）与策略/执行分离

### 2.1 决策总表

| # | 决策 | 摘要 |
|---|------|------|
| D-1 | 池形态 = 预建立 + 借出即消费，**不归还** | §1.2 结构约束的直接结论；不做伪"归还复用" |
| D-2 | 键 = 传输身份 `(server, port, tls, sni, skip_cert_verify, alpn)`，非出站名 | "同出口同 SNI" 字面落地；direct 键 = (target_host, target_port, tls=false)；键作用域自失效（D-10） |
| D-3 | 策略/执行分离（对齐 [obfuscation-middleware.md](obfuscation-middleware.md) §2.1 方法论） | 配置期策略 / 运行期执行 / 协议绑定三侧职责钉死（§2.3） |
| D-4 | 零 trait 变更 | 不动 `EgressConnector`/`FlowOutput`/`FlowMiddleware`/`ConnectorFlowOutput`；连接器构造注入 `Option<Arc<…>>` |
| D-5 | TLS 会话恢复 = 进程级共享 `ClientConfig` 工厂 | `tls.rs` 每流重建是恢复失效根因（§2.4）；`HandshakeKind` 公开 API 观测 |
| D-6 | MVP 能力矩阵 | 池化 = trojan/http/vless + direct 选通；不池化 = socks5/ss/hy2/wg/vmess（§2.5） |
| D-7 | 预热：TLS 出站装配即预热；direct 不预热 | TLS 出站键装配期已知；direct 目标未知，流量驱动（首次 miss 后补充供后续命中） |
| D-8 | `connection_pool_size` 收编 = 全局 idle 容量缺省 | 块存在且未写 `max_idle_global` → 取 `RuntimeConfig.connection_pool_size`（缺省 1024） |
| D-9 | 关闭态零差异 | 无块 → 连接器 pool=None、tls 走今天每流路径，字节级行为不变（§2.6） |
| D-10 | 池与工厂 = 进程级单例跨热更新共享；参数变更重启生效 | :720/:933 只重连装配不重建池（订阅 30s 周期刷新不杀 warmth，§4.3） |
| D-11 | stale 处置 = 借出即失效 → 一次性前台重拨；不做主动探活 | 协议绑定首写/首读失败判 stale：释放+计数+重拨一次；再失败 → Err（同今天拨号失败语义） |

### 2.2 池形态与键（D-1/D-2）

- **池不变量**：idle 条目零协议字节写入（借出后连接处于干净状态，协议头由连接器写入）——这是池与协议层的唯一契约；
- 键含 `alpn`/`skip_cert_verify`（影响握手形态 → 属传输身份）；不同出站名撞同一传输身份（如 direct 到 X:443 平文 vs http 代理在 X:443 平文）共享键空间——语义等价（同为到 X:443 的裸 TCP），无害且有益；
- `TransportKey` 的可读序列化（控制面/日志用）：`tls?sni@server:port[alpn=..]` 形状。

### 2.3 策略/执行分离（D-3/D-4）

| 侧 | 载体 | 职责 | 不做什么 |
|----|------|------|---------|
| 策略侧（配置/装配期） | `EgressPoolBlock`（seep-config）→ `PoolPolicy`（转换在 seep-runtime，先例 `to_padding_policy()`） | 谁参与（`enabled`/`pre_dial_direct`）、容量（per-key/global）、水位、超时、会话缓存容量 | 不含任何运行期状态 |
| 执行侧（运行期） | `TransportPool`（seep-protocols/src/pool.rs） | 拨号/缓存/借出/水位补充/回收/退避/计数 | **零协议知识**（只认识 `TransportKey`，不见协议字节） |
| 协议绑定侧 | 既有连接器（trojan/http/vless/direct） | 借出后写协议头 + `copy_bidirectional`（现状语义不变） | 不感知池内部（只见 `acquire` API） |

对齐 P1-4 §2.1 的同款裁决逻辑：P1-4 因 `handle(Flow)` 流签名不承载帧语义而分离策略与执行；本条目因连接器绑定语义各异而把"传输会话"从连接器中分离——两次分离共同点：**零 trait 变更**（D-4，seep-core 面完全不动）。

### 2.4 TLS 会话恢复（D-5）

**根因（源码核对，rustls 0.23.35）**：`Resumption::in_memory_sessions(num)` 是 rustls 的**默认恢复策略**（`client/client_conn.rs`："This is the default `Resumption` choice"，内部即 `handy::ClientSessionMemoryCache`）——即默认配置本就支持会话恢复；失效根因在 seep 侧：`tls.rs:10-47` 每次 `create_tls_connector[_with_alpn]` 新建 `ClientConfig`，会话缓存（`Arc<dyn ClientSessionStore>`）活在实例内，**随流销毁**——ticket 存不进下一次握手。调用点：trojan.rs:101、http.rs:92、vless.rs:190/:228。

**修复**：`TlsConnectorFactory`（seep-protocols/src/tls.rs 内扩展）：

```rust
pub struct TlsConnectorFactory {
    configs: Mutex<HashMap<TlsConfigKey, Arc<ClientConfig>>>,  // key = (skip_cert_verify, alpn 规一化)
}
impl TlsConnectorFactory {
    /// 同键返回共享 Arc 的 TlsConnector（TlsConnector::from(Arc<ClientConfig>) 为廉价克隆）
    pub fn connector(&self, skip_cert_verify: bool, alpn: Option<&[String]>) -> Result<TlsConnector>;
}
```

- 共享实例上默认恢复策略即刻生效（缓存跨流存活）；显式 `config.resumption = Resumption::in_memory_sessions(session_cache_size)` 钉容量（配置项 §3）；
- **观测（公开 API，已核对）**：`CommonState::handshake_kind() -> Option<HandshakeKind>`（`common_state.rs:188`），变体 `Full` / `FullWithHelloRetryRequest` / `Resumed`（`rustls` lib.rs:545 公开导出）；tokio-rustls `TlsStream::get_ref().1` 可达——拨号完成即读，驱动 `seep_tls_handshakes_total{type}`；
- 生效门：块存在且 `tls_resumption: true`（默认）即注入工厂——**独立于 `enabled`**（enabled=false 只关池，会话恢复是纯增益单独留开，见 §2.6 零差异边界）；无块 → 工厂不注入，连接器走今天每流路径（D-9）；
- 与 P2-5 互指：uTLS 的挂点就是 `tls.rs`（todo P2-5 明示）；工厂把 `ClientConfig` 构造收敛到一处后，恰为指纹替换的注入面——本条目为其铺路不越界。

### 2.5 能力矩阵（D-6/D-7）

| 出站 | MVP 处置 | 依据（§1.1 可拆性） |
|------|---------|---------------------|
| trojan / http（含 tls）/ vless（tcp+ws，含 tls） | **池化**（装配注入池+工厂） | 绑定在传输建立后，天然可拆 |
| direct | **选通池化**（`pre_dial_direct`，默认 false） | 键=target；投机预拨对目标产生"未请求的连接"，对外观感与成本由开关显式承担（R-pool2） |
| socks5 / shadowsocks | 不池化（记扩展） | crate 合并拨号+绑定；socks5 无 TLS 层收益仅 1-RTT |
| hysteria2 / wireguard / vmess | 不池化（各自归 V2 mux / 系统接口 / 未实现条目） | 非 TCP 传输模型 |

预热（D-7）：`enabled=true` 时装配尾部对已知 TLS 出站键各拨 `min(max_idle_per_key, …)` 条 warm（失败退避重试，不阻塞启动——池是优化不是前置条件）；direct 不预热。

### 2.6 关闭态零差异（D-9）

- 无 `egress_pool:` 块（存量配置）：解析 None → 连接器 pool=None、工厂=None → `TcpStream::connect` + 每流 `create_tls_connector` 与今天逐字节同路径；
- 块存在 `enabled: false`：仅 `tls_resumption`（默认 true）生效——共享工厂注入（恢复跨流生效），池不构造；
- 上述两态均有行为对照断言（§8.1）——"零差异"可证，非口头承诺。

## 3. 镜像类型与 schema（seep-config）

### 3.1 区块形状

```yaml
egress_pool:
  enabled: false              # 池总开关（默认关，对齐 udp:/obfuscation: 先例）
  tls_resumption: true        # 共享 ClientConfig + 会话缓存；块存在即生效，独立于 enabled
  max_idle_per_key: 2         # 每键 idle 上限（预热/补充目标）
  # max_idle_global: 1024     # 全局 idle 上限；未写 → 取 RuntimeConfig.connection_pool_size（D-8）
  low_watermark: 1            # 借出后 idle 低于此值即触发补充（≤ max_idle_per_key）
  idle_timeout_secs: 30       # idle 条目寿命（自入池起算）
  dial_timeout_secs: 5        # 单次拨号超时（TCP+TLS 全程）
  session_cache_size: 256     # ClientSessionMemoryCache 容量
  pre_dial_direct: false      # direct 按 target 预拨（投机拨号，默认关，§2.5）
```

### 3.2 镜像与转换（裁决：镜像而非加依赖，先例 udp-dataplane §5.2）

seep-config 零依赖 seep-core/protocols（现状 deps 仅 anyhow/serde 系）：**seep-config 定义镜像 serde 类型，seep-runtime 增 `to_pool_policy()` 转换**（`PoolPolicy` 类型定义在 seep-protocols/src/pool.rs——该 crate 需 tokio 拨号；seep-protocols 已依赖 seep-config，无新依赖边）。

| config 镜像类型（seep-config） | 转换产物 |
|-------------------------------|---------|
| `EgressPoolBlock { enabled, tls_resumption: Option<bool>, max_idle_per_key: Option<usize>, max_idle_global: Option<usize>, low_watermark: Option<usize>, idle_timeout_secs: Option<u64>, dial_timeout_secs: Option<u64>, session_cache_size: Option<usize>, pre_dial_direct: Option<bool> }` | `PoolPolicy { …全字段具值 }`（`to_pool_policy(default_global: usize)`，default_global = `runtime_config.connection_pool_size`，D-8） |
| `SeepConfig.egress_pool: Option<EgressPoolBlock>`（`#[serde(default)]`） | `None` → 不构池不注工厂（零差异）；`Some` 且 enabled → `Some(Arc<TransportPool>)`；`Some` 且 tls_resumption → `Some(Arc<TlsConnectorFactory>)` |

### 3.3 校验（构建期，`EgressPoolBlock::validate`）

1. `enabled=false` 且 `tls_resumption=false` → 后续容量/水位字段无视（不报错，容忍半成品）；
2. `max_idle_per_key == 0`、`low_watermark > max_idle_per_key`、`session_cache_size == 0`（resumption 开时）→ Err（E1）；
3. `idle_timeout_secs < dial_timeout_secs` → warning（不 Err：条目寿命短于拨号时长只是预热浪费，非错误）；
4. `pre_dial_direct=true` 但 `enabled=false` → Err（无池则无从预拨，防配置幻觉）。

### 3.4 兼容

- 存量配置无 `egress_pool:` → None 缺省，行为零差异（serde 往返钉住，同 udp 块先例）；
- **`EgressPoolBlock` 加 `#[serde(deny_unknown_fields)]`**（新块无存量负担，拼错子字段立刻报错，对齐 network-route §1.5）；全局 `SeepConfig` 维持宽松。

## 4. 装配与热更新

### 4.1 build() 装配落点

`RuntimeBuilder::build()`（`runtime_builder.rs:105`）在 `build_egress_outputs` 调用点（:158）之前，紧邻 UDP 块的既有模式：

```
let egress_pool_cfg = config_snapshot.egress_pool;          // Option<EgressPoolBlock>
let tls_factory = egress_pool_cfg.as_ref()
    .filter(|b| b.tls_resumption().unwrap_or(true))
    .map(|_| Arc::new(TlsConnectorFactory::new(policy.session_cache_size)));
let transport_pool = egress_pool_cfg.as_ref()
    .filter(|b| b.enabled)
    .map(|b| Arc::new(TransportPool::new(b.to_pool_policy(
        self.runtime_config.connection_pool_size.unwrap_or(1024)), tls_factory.clone())));
// build_egress_outputs(&config_snapshot.egress, transport_pool.clone(), tls_factory.clone())
```

- `build_egress_outputs`（:1635）签名增两参；各 match 臂构造连接器时传入（trojan/http/vless 恒传；direct 仅 `pre_dial_direct` 时传池）——**`ConnectorFlowOutput`（:1466）与 `FlowOutputRouter`（:1227）零改动**（D-4）；
- Runtime 增两字段持有单例 + getter（`get_transport_pool()` / `get_tls_factory()`，`get_mesh_registry` :259 / `get_chain_manager` :386 先例），控制面与热更新闭包取克隆；
- 装配尾 warm()（D-7）：对配置内 TLS 出站逐键预拨，spawn 后台任务（失败退避，不阻塞启动）。

### 4.2 连接器接入形态（以 trojan 为例）

```rust
// 构造签名增两 Option（None = 旧行为逐字节路径，D-9）
TrojanConnector::new(server, port, password, sni, skip_cert_verify,
                     pool: Option<Arc<TransportPool>>, factory: Option<Arc<TlsConnectorFactory>>)

async fn forward(&self, flow: Flow) -> Result<FlowReport> {
    let key = TransportKey::tls(&self.server, self.port, &self.sni, self.skip_cert_verify, &[]);
    // 借出（hit 弹 idle / miss 前台拨号）+ 水位补充；两参 None 时走今天内联路径
    let (mut outbound, _lease) = self.pool.acquire(&key).await?;   // _lease: Drop 时 leased--
    match self.bind_and_relay(flow, &mut outbound).await {          // 写 trojan 头 + copy_bidirectional
        Err(e) if 首写首读失败 && self.pool.is_some() => {
            self.pool.note_stale(&key);                             // 计数 + 释放（lease drop）
            let (mut fresh, _lease) = self.pool.acquire_fresh(&key).await?;  // 一次性重拨（D-11）
            self.bind_and_relay(flow, &mut fresh).await
        }
        other => other,
    }
}
```

- `LeaseGuard`：checkout 返回 `(BoxedIo, LeaseGuard)`，guard Drop 递减 leased gauge——连接器只多持一个 `_lease` 绑定，RAII 无需显式归还调用（也无归还语义，D-1）；
- http 同形（`perform_connect` 泛型直接吃 BoxedIo）；vless 两分支（tcp/ws）同形，ws 的 upgrade 在借出后进行（host/path 目标无关，§1.1）；direct：`TcpStream::connect(target)` → `pool.acquire(TransportKey::plain(target))`。

### 4.3 热更新语义（D-10）

- 两处重建路径（:720 订阅合并、:933 配置 apply）重跑 `build_egress_outputs`——**只重连装配（传/撤句柄），不重建池与工厂**：进程级单例 + 键作用域自失效（换 server/sni → 新键 ≠ 旧键 → 旧条目无人借出，idle 超时自然回收，§5）——:720 的订阅刷新默认 30s 周期，若随重建杀池会持续杀掉 warmth，故单例是必须而非优化；
- `enabled`/`pre_dial_direct`/出站集变更：随装配即时生效（新连接器带/不带句柄）；
- **池参数（容量/水位/超时/缓存容量）烧在构造期，变更需重启**（对齐 network-route O-hot / P0-5 §1.6 先例）；块整体移除 → 新装配不传句柄，池随 Runtime 释放，idle 条目关闭（E7）。

## 5. 状态机

### 5.1 连接生命周期

```
        [warm 预热 / refill 水位补充 / 前台 miss]（origin 三值入 dials_total）
                    dial ──ok──► idle ──acquire──► leased ──协议绑定+copy──► consumed（TCP close，不回池）
                     │                            │
                     │ err                         │ 绑定首写/首读失败 = stale
                     ▼                            ▼
              backoff（1s 起指数，30s 封顶，      note_stale：释放（lease drop）
              成功即复位；仅后台补充走退避，        + stale_redial 计数
              前台 miss 失败直接 Err=今天语义）    + acquire_fresh 一次性重拨（D-11，再失败 → Err）
                     ▲
   idle：lazy 弹出时校验 expiry（过期 → close + miss）+ 周期 sweep（idle_timeout/2）回收过期与孤儿键条目
   容量：refill/入池时全局 idle 超 max_idle_global → 逐最老 idle 驱逐（不拒新——池是优化不是配额）
```

### 5.2 状态与不变式

- 单连接状态集：`dialing → idle → leased → consumed|closed`（leased 为终态前唯一活跃态；无 returned 态——D-1）；
- 池级不变式：`Σ(idle) ≤ max_idle_global`；`idle(k) ≤ max_idle_per_key`；`inflight_refill(k) ≤ max_idle_per_key − idle(k)`（水位补充的并发上限，消费风暴下每流至多补一条、总量有界 = 总拨号 ≈ 流数）；
- 补充触发点 = **acquire（弹出后）**；consume（lease drop）只调 gauge 不触发补充——避免"流结束"与"下次流来"间的空窗期盲目拨号。

## 6. 控制面

### 6.1 `/metrics` 新序列（封闭标签，R11；渲染挂 `handle_metrics` :245，与 `seep_mesh_*` :319 同族）

```
seep_pool_acquires_total{result="hit|miss|stale_redial"}
seep_pool_dials_total{origin="foreground|warm|refill", result="ok|error"}
seep_pool_idle_connections        # gauge
seep_pool_leased_connections      # gauge
seep_pool_reuse_ratio             # gauge = hits/(hits+miss)，启动至今
seep_pool_evicted_total{reason="idle_timeout|capacity|shutdown"}
seep_tls_handshakes_total{type="full|resumed|full_hrr"}   # 工厂启用时；HandshakeKind 三变体直映
```

### 6.2 `GET /egress/pool/stats`（match 臂对齐 `/chains/dry-run` 先例）

```json
{"enabled": true, "tls_resumption": true,
 "keys": [{"key": "tls:sni=x@example.com:443", "idle": 2, "leased": 1}],
 "counters": {"hit": 9, "miss": 1, "stale_redial": 0, "dials_ok": 12, "dials_err": 0},
 "reuse_ratio": 0.9}
```

数据源 = `Runtime::get_transport_pool()` 快照方法（§4.1 getter 先例）；鉴权继承控制面现状。`seepctl pool status` 子命令非 MVP（记 §11 O-pool3）。

## 7. 错误路径

| # | 错误点 | 条件 | 语义与恢复 |
|---|--------|------|-----------|
| E1 | 配置非法 | 水位>每键上限 / 零容量 / `pre_dial_direct` 无池 | 构建期 Err 带字段名（§3.3） |
| E2 | 前台拨号失败 | TCP/TLS 超时或拒（miss 或 stale 重拨） | 向连接器返回 Err → 流失败（**同今天拨号失败语义**，池不吞错）+ `dials_total{origin=foreground,result=error}` |
| E3 | 借出即失效（stale） | idle 连接被对端关闭（keep-alive 超时） | 释放 + `acquires_total{stale_redial}` + `acquire_fresh` 一次性重拨；再失败 → E2 |
| E4 | 后台补充拨号连续失败 | 出站不可达 | 指数退避 1s→30s 封顶，成功复位；**不阻塞 acquire**（miss 走前台）+ 计数 |
| E5 | 全局容量驱逐 | idle 超 `max_idle_global` | 逐最老 idle 关闭 + `evicted_total{capacity}`（不拒新） |
| E6 | idle 超时 | `idle_timeout_secs` 到期（lazy + sweep 双路径） | 关闭 + `evicted_total{idle_timeout}`；热更新孤儿键靠此自然排空 |
| E7 | 热更新/块移除 | 句柄撤出或池释放 | 池随最后句柄 drop → idle 全关 + `evicted_total{shutdown}`；借出中连接随流自然终结（不等待） |
| E8 | 工厂构建失败 | root store/verifier 异常 | 构建期 Err（同今天 `create_tls_connector` 失败，但提前到装配期暴露） |
| E9 | 转发中连接错误 | `copy_bidirectional` Err | 连接终态消耗（不回池）+ leased 归零（lease drop）；后台补充照常 |
| E10 | 关闭路径 | 无块 / enabled=false | 非错误：pool=None、工厂按 tls_resumption 注入；行为对照断言钉住（§2.6） |

## 8. 测试策略

### 8.1 单测（无特权，任何环境）

- **schema**：无块旧配置解析 ✓；含块 roundtrip ✓；未知子字段 deny ✓；§3.3 四条校验两态 ✓；`to_pool_policy` 缺省填充（含 D-8 映射：未写 global → 1024/自定义 connection_pool_size）✓；
- **键**：相等性（sni/alpn/skip/端口敏感；alpn 顺序规一化）；direct 平文键与 TLS 键不撞；可读序列化形状；
- **池核心**：hit/miss 计数与 acquire 语义；水位补充（弹出后 inflight 上界 = 每键不变式）；per-key/global 驱逐顺序（最老先逐）；idle 超时（**MockClock**，循 P0-1 测试形态）lazy 与 sweep 双路径；退避曲线（1s→30s 封顶、成功复位）；stale 一次性重拨（重拨再失败 → Err，不再三试）；reuse_ratio 计算；
- **工厂**：同 (skip,alpn) 两次 `connector()` 底层 `Arc` 同实例（ptr_eq）；异键异实例；alpn trim/空项过滤（对齐 tls.rs 既有行为）；
- **连接器（None/Some 两态）**：pool=None 路径与今天逐字节同构（mock 出站对照断言，D-9 关闭态证明）；Some 路径 acquire→绑定→relay 时序。

### 8.2 集成（loopback，无特权——对照 TUN 系无需 skip 守卫）

- **验收主场景**：mock trojan TLS 服务端（自签证书：rcgen dev-dep 或内嵌静态 PEM，实施时二选一记 §10）+ `egress_pool: {enabled: true}` → N=10 串行同目标请求 → 断言 `acquires{hit}≥9`、`{miss}≤1`、`reuse_ratio≥0.9`、**前台 dial 计数增量 ≤1**（判据 1/2）；
- **会话恢复**：同工厂两次拨号 → 第二次 `handshake_kind() == Resumed`（公开 API 直断，§2.4；服务端握手字节量对比作交叉验证可选项）；
- **对照关闭态**：同场景 `enabled: false`（无块）→ 前台 dial = N、无 `seep_pool_*` 序列、行为与主干基线一致（判据 4）；
- **stale**：服务端主动关 idle 连接 → 下一请求 `stale_redial` 计数 +1 且请求成功（E3）；
- **热更新**：换 egress server 触发 :933 路径 → 新请求拨新键、旧键条目 idle 超时回收（短超时配置 + MockClock 或真实等待）；池单例不重建（实例 ptr 断言，warmth 存活）。

### 8.3 门禁

- 全部 loopback 单测化，无特权依赖（CI 常规跑）；全仓基线（P0-3 时点 118 项 + 后续增量）零回归——本条目为增量，None 路径不改既有行为（§2.6）；
- 关闭态对照断言必须存在（否则"零差异"不可证，同 P1-4 E11 纪律）。

## 9. 分步实施清单（M0–M5）

提交节奏循 P0-4 §9.1.1 / tun-dataplane §5 铁律：每步 `cargo build` + `cargo test` 全绿 → 单条 commit（引用本文 §节）→ `git fetch origin main` + rebase → push → 下一步；禁 tag/release/force push。

> **落地注记（2026-10-02）**：M0–M5 已全部落地（M0 `0ecb477` / M1 `d1d0478` / M2 `97dbdf7` / M3 `1e90d04` / M4 `54df7cc` / M5 本提交），实施期偏差逐条记入 §10-11..§10-17；门禁基线 `cargo test --workspace --all-features` 259 项全绿。

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| M0 | seep-protocols `pool.rs`：`PoolPolicy`/`TransportKey`/`TransportPool`（acquire/acquire_fresh/水位补充/idle sweep/驱逐/退避/计数/LeaseGuard）+ `tls.rs` `TlsConnectorFactory`（共享 ClientConfig + `in_memory_sessions` + HandshakeKind 计数） | — | 8.1 池核心与工厂全绿 |
| M1 | seep-config：`EgressPoolBlock` + deny + validate + `SeepConfig.egress_pool`；seep-runtime：`to_pool_policy()`（D-8 映射） | M0 | 8.1 schema/转换全绿；旧配置零差异 |
| M2 | 连接器接入：trojan/http/vless/direct(选通) 构造签名增两 `Option`，forward 拨号点改 acquire + stale 一次性重拨（None 路径 = 旧行为） | M0 | 8.1 连接器两态全绿；既有出站测试零回归 |
| M3 | 装配与热更新：build() 构池/工厂、`build_egress_outputs` 增参（:158/:720/:933 三调用点）、Runtime 持有 + getter、装配尾 warm() | M0–M2 | 8.1 装配两态；热更新键自失效与单例存续断言 |
| M4 | 控制面 + 验收脚本：`/metrics` 渲染 + `GET /egress/pool/stats` + 统计脚本（§0.2 三组数）+ 8.2 集成全套 | M3 | 8.2 全绿；判据 1–3 可复现 |
| M5 | 文档回填：PROTOCOLS.md 总表/性能节连接池行、roadmap S2/S3 进度、todo 勾选、本文 §10 偏差回填 | M0–M4 | P1-5 验收全表逐条核对（§0.2） |

## 10. 偏差与假设（信息缺失处的自行假设均已注明）

| # | 类型 | 内容 |
|---|------|------|
| 1 | 裁决 | 池形态 = 预建立 + 借出即消费不归还（§1.2 结构约束推导；不伪造"归还复用"）；总拨号 ≈ 流数如实写进验收口径（§0.2 注记） |
| 2 | 裁决 | 键 = 传输身份而非出站名（D-2）；撞键语义等价无害 |
| 3 | 裁决 | 策略/执行分离 + 零 trait 变更（D-3/D-4，方法论对齐 P1-4 §2.1；`ConnectorFlowOutput`/`FlowOutputRouter` 不动） |
| 4 | 核对 | 恢复根因 = 每流新建 ClientConfig 使默认会话缓存随流销毁（rustls 0.23.35 源码：`Resumption::in_memory_sessions` 为默认策略）；观测走公开 `handshake_kind()`——均已对照 Cargo.lock 版本源码核验，非推测 |
| 5 | 裁决 | 能力矩阵 MVP = trojan/http/vless + direct 选通（D-6）；socks5/ss 因 crate 合并拨号+绑定不进 MVP（tokio_socks/shadowsocks 公开 API 无外部流注入口——基于公开面判断，实施期如发现注入口可平滑升级，不阻塞） |
| 6 | 裁决 | 池/工厂进程级单例跨热更新共享；参数变更重启生效（D-10，先例 network-route O-hot） |
| 7 | 裁决 | `connection_pool_size` 收编为全局容量缺省（D-8）——孤儿字段首个消费者，关闭态仍零消费零行为 |
| 8 | 裁决 | stale = 一次性前台重拨，不做主动探活（D-11）：预建立连接上主动 read 有消费边界歧义（TLS post-handshake 消息），重试以更低复杂度覆盖同场景 |
| 9 | 假设（已收口） | 集成测试自签证书生成方式 → **实施选定 rcgen dev-dep**（`generate_simple_self_signed` + rustls-pemfile 解析，M4 `54df7cc`）；并发验收面（判据 1–3 串行形态）已可复现 |
| 10 | 假设（部分收口） | 预热/补充拨号的并发有界性由每键不变式保证（§5.2），不做全局拨号速率限流——串行验收已过（M4）；真并发压测依赖真实出口流量形态，本仓 loopback 集成测不构造，R-pool3 观测面（dials/idle/leased gauge）已备，登记待真实流量期核 |
| 11 | 偏差 | §6.2 `keys[]` 不含 per-key `leased`：D-1 借出即消费下 leased 归全局 gauge 记账（`seep_pool_leased_connections`），分键 leased 无运营动作，`KeySnapshot{key,idle}` 即终形（M4） |
| 12 | 偏差 | `acquire_bound` 的 bind 闭包取 `FnMut(&mut dyn IoStream) -> Pin<Box<dyn Future>>` 装箱形而非 `AsyncFnMut`：当前 rustc（1.99）对 async 闭包 HRTB 泛化不过（"AsyncFnMut is not general enough"），装箱 future + `&mut dyn`（非 `&mut BoxedIo`——Box 内层 'static 固定）为稳定习语（tower service 同形，M2） |
| 13 | 裁决 | direct 无 stale 一次性重拨：bind 语义 = 首写首读，direct 无协议握手期 → 无 stale 判定点，死闲连接暴露为流错误由 idle_timeout 兜底（M2 注释载明） |
| 14 | 偏差 | warm 预热 + 周期 sweeper 挂 `Runtime::start()` 而非 `build()`：build() 为同步装配无 tokio 上下文，spawn/prewarm 须运行时在位（M3） |
| 15 | 缺陷修复 | 实施期发现既有出站 TLS 首拨即崩的潜在生产缺陷：依赖图特征统一后 rustls 同持 ring 与 aws_lc_rs 两特征，`ClientConfig::builder()` 在双提供方歧义下运行时 panic（rustls crypto/mod.rs）——修复 = `tls.rs` OnceLock 显式安装 ring 默认提供方 + `builder_with_provider` 构造（M0）；mock 服务端同法（M4 测试） |
| 16 | 偏差 | 水位补充拨号失败退避 + 有界重试：`spawn_fill` 单轮至多 `MAX_FILL_ATTEMPTS=5` 次尝试（退避 1s 起指数 30s 封顶，成功复位），防服务端持续不可达时的空转拨号风暴（M0） |
| 17 | 观测注记 | rustls 对无 close_notify 的裸 EOF 视 `UnexpectedEof`（严格校验，0.22+ 行为）：`copy_bidirectional` 以 Err 收场——既有内联路径同形非池化引入；真实 trojan/http 上游普遍发送 close_notify，mock 服务端收尾显式 shutdown 发 close_notify（M4 测试注记） |

## 11. 风险与未决

- **R-pool1（核心）**：预建立连接被中间盒/服务端半开或关闭（idle 窗口内死亡）——`idle_timeout_secs=30`（低于常见服务端 idle 上限）+ stale 一次性重拨兜底；stale 率经 `acquires_total{stale_redial}` 可见，超阈值时操作者应调低每键上限或缩短 idle；
- **R-pool2**：direct 投机预拨对目标产生"未请求的连接"（对外观感接近扫描、占用服务端连接配额）——默认关（`pre_dial_direct=false`），开启者显式承担；
- **R-pool3**：借出/回收的并发竞态（gauge 与容量记账）——原子计数 + 锁窗口内重检，并发压测循 P0-1 形态（M0）；
- **R-pool4**：池化改变连接-请求时序（连接先于请求存在）——对 trojan/http/vless 服务端无协议差异（首字节仍是协议头）；DPI 视角的时序相关性分析归混淆层讨论，本条目不声称；
- **O-pool1**：mesh hop 拨号复用（`connect_next` 形状兼容：键=hop 地址、MeshEnvelope 首写即绑定）——非承诺，需求出现再议；
- **O-pool2**：socks5/shadowsocks 接入（crate 外部流注入口核查后同 vless 形状）；
- **O-pool3**：`seepctl pool status` 子命令（端点已交付，CLI 包装随需求）；
- **O-pool4**：hy2/QUIC 会话复用（与 V2 多路复用统一设计，本条目明确不降总连接数的另一半答案）。
