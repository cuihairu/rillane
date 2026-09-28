# S1 UDP 全链路设计稿（UDP Data-Plane）

> 状态：设计稿（2026-09）· 对应 [roadmap.md](roadmap.md) S1 · 覆盖 [todo.md](../../todo.md) P0-1..P0-5
> 上游文档：[positioning.md](positioning.md)（定位与缺口 G1）· [architecture.md](../architecture.md)（crate 划分与关键接口）· [mesh.md](../mesh.md)（TCP 数据面/envelope/mTLS）· [PROTOCOLS.md](../PROTOCOLS.md)（能力声明，部分超前，见 §0.2 状态标注）
> 本轮为设计稿：不改任何源码；文中"新增"均为实施轮工作量。

## 执行摘要

当前数据通路是纯 TCP：入站 socks5 显式拒绝 UDP ASSOCIATE（`inbound/socks5.rs` 仅接受 cmd=0x01），出站 hy2/wg 按 `TargetProto` 分派后对非 TCP 报错，mesh 数据面 `MeshStream` 绑定 `AsyncRead+AsyncWrite`。本稿给出不破坏 TCP 面的 UDP 平行面设计：

1. **`seep-core` 新增 UDP 会话层**（NAT 式会话表 + 粘滞键 + 平行 trait `EgressUdpConnector`）——因为 `Flow.io: BoxedIo` 是流语义，UDP 无法复用；
2. **socks5 入站补 0x03 命令**，复用现有认证/解析框架；
3. **四个 UDP-capable 出站**（direct/ss/hy2/wg），其余类型 UDP 路由时构建期报错；
4. **mesh UDP 面**：首包携带路径、后续包仅 flow_id 的跳间缓存转发，envelope 二进制化从 UDP 面开始（MTU 硬约束），与 P2-6 合流；
5. **观测/配置**：顶层 `udp:` 区块 + `/metrics` 新增 `seep_udp_*` 指标序列。

设计原则：UDP 面与 TCP 面在同一进程内**并行共存**，共享 Flow 会话模型、路由引擎、控制面与订阅；不存在分支产品路径（positioning.md §2.5）。

---

## 0. 总体视图与现状标注

### 0.1 数据流总图

```
              TCP 面（现状，不动）                UDP 面（本稿新增）
应用 ──► socks5/http/mixed ─┐          应用 ──► socks5 UDP ASSOCIATE ─┐
                            │                                        │
                        Flow(io)                            UdpSession(会话表+粘滞键)
                            │                                        │
                     FlowRouter（共用，传输无关） ◄──────────────────┘
                            │                                        │
                     EgressConnector                     EgressUdpConnector
                     (direct/ss/trojan/hy2/vless/wg)     (direct/ss/hy2/wg)
                            │                                        │
                     mesh TCP data-plane                 mesh UDP data-plane
                     (MeshEnvelope JSON, mTLS)           (UdpEnvelope 二进制, 加密见 §4.4)
```

### 0.2 交叉引用与 PROTOCOLS.md 状态标注

| 声明出处 | 状态 | 本稿处置 |
|---------|------|---------|
| PROTOCOLS.md「SOCKS5 … UDP ASSOCIATE (UDP 代理)」 | **超前描述**（代码仅 CONNECT） | §2 落地；落地后状态改为"已实现" |
| PROTOCOLS.md「Shadowsocks … TCP, UDP」 | 部分超前（仅 TCP） | §3.2 落地 |
| PROTOCOLS.md「Hysteria … UDP 首包优化」/ hy2 小节 | 超前（仅 TCP） | §3.3 落地；依赖 `hysteria2` crate 能力，见未决项 V1 |
| PROTOCOLS.md「WireGuard … Layer 3 (IP) 隧道」 | 与实现一致（TCP over WG 已通） | §3.4 扩展 UDP 包封装 |
| PROTOCOLS.md「SOCKS5 出口 … UDP 中继」 | 超前 | **不在 S1 范围**，见 §3.5 |
| mesh.md「Mesh Data-Plane Protocol (TCP, MVP)」 | 与实现一致 | §4 平行扩展 UDP 面，TCP 面契约不变 |
| architecture.md「下一阶段 … UDP 等」 | 计划中 | 本稿即其设计 |

## 1. UDP 会话表与粘滞键（P0-1）

> 实现级展开：[udp-session-table.md](udp-session-table.md)（两级映射结构、粘滞键优先级与决策失效、回收状态机、FlowSession 逐字段集成与测试清单）。

### 1.1 复用

| 现有资产 | 用途 |
|---------|------|
| `seep-core::TargetProto::{Udp, Quic}` | 枚举已存在，直接作为会话目标协议标记（TUN 阶段 Quic 识别时区分标记，转发面同为 UDP 数据报） |
| `seep-core::FlowTarget` | 会话内每个目标映射复用该结构 |
| `seep-core::FlowSession`/`SessionUsage`/`FailureStats` | 会话统计与失败记录字段直接挂到 UDP 会话上 |
| `seep-core::FlowRouter`/`FlowMiddleware` | 路由决策与中间件对 UDP 面同样生效（传输无关） |
| workspace 依赖 `dashmap 6.0` | 会话表容器 |
| `seep-routing::RoutingEngine` | 不改；UDP 会话首包走同一路由决策 |

### 1.2 新增（`seep-core` 新模块 `udp.rs`）

```rust
pub struct UdpSessionKey {           // 粘滞键
    pub client: SocketAddr,          // 入站客户端源地址（IP:port）
    pub client_id: Option<String>,   // socks5 认证用户名（可选维度）
}

pub struct UdpSession {
    pub key: UdpSessionKey,
    pub decision: Arc<RouteDecision>,// 首包路由决策缓存 —— 会话粘滞的核心
    pub mappings: LruCache<FlowTarget, UdpMapping>,  // NAT 式目标映射
    pub session: FlowSession,        // 复用统计
    pub last_activity: Instant,
    pub expires_at: Instant,
}

pub struct UdpSessionTable { /* DashMap<UdpSessionKey, UdpSession> + 后台回收任务 */ }

#[async_trait]
pub trait EgressUdpConnector: Send + Sync {
    fn name(&self) -> &'static str;
    /// 建立到目标的 UDP 关联，返回可收发的 relay 句柄
    async fn associate(&self, ctx: FlowContext) -> Result<Box<dyn UdpRelay>>;
}

#[async_trait]
pub trait UdpRelay: Send {
    async fn send_to(&self, target: &FlowTarget, buf: &[u8]) -> Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(FlowTarget, usize)>;
}
```

**设计决策——平行 trait 而非扩展 `EgressConnector`**：现有 `EgressConnector::forward(flow: Flow) -> FlowReport` 语义是"接管 `Flow.io` 中的流、双向拷贝、返回即结束"（8 个 TCP 实现依赖此契约）。UDP 会话是长驻、面向数据报、单客户端 socket 对多目标的（NAT 语义），塞进同一 trait 需要给所有 TCP 实现加空实现并弱化类型安全。平行 `EgressUdpConnector` 让 TCP 面零改动（共存方式）。

**粘滞语义**：同一 `UdpSessionKey` 的所有包命中同一 `RouteDecision`（缓存于会话），游戏会话不因逐包重新路由而跳链路。粘滞键的**进程维度**（todo P0-1 提及"进程/五元组"）依赖 P1 TUN 才能取得进程信息，S1 落地为 `client addr + 可选用户名`，结构体预留 `process_id: Option<u32>` 字段，P1 填充——已在结构上兼容，不需二次迁移。

**超时回收**：后台 tokio interval 任务扫描（复用 `seep-runtime` 现有后台任务模式，参照 `ChainManager::start_health_check_task`）。默认值：会话空闲 180s 回收；会话内单目标映射空闲 60s 移除（游戏心跳间隔远小于此）；单节点最大并发会话默认 4096，超限拒收并计数（见 §5 指标）。

### 1.3 与 TCP 面共存

- `FlowSession`/`ChainContext` 实例可共享（同一客户端既有 TCP 又有 UDP 流量时统计合流）；
- 会话表独立于任何 TCP 连接状态机，`FlowOutput` TCP 路径不感知；
- 路由引擎无传输分派逻辑，UDP 首包照常产生 `RouteDecision`（含 `mesh.` 目标升级为 `Chain`）。

### 1.4 验收标准（对齐 todo P0-1）

- 会话创建/查询/超时回收有单元测试：空闲超 `session_timeout` 后表项消失；活跃会话不回收；
- 同一粘滞键连续发包复用同一 `RouteDecision` 与映射，不重建（断言表内映射计数不变）；
- 超限拒收有计数指标（`seep_udp_packets_dropped_total{reason="session_limit"}`）。

### 1.5 风险与未决项

- **R1 LRU 容量与抖动**：目标映射 LRU 容量默认建议 256/会话，需在压测中确认游戏场景（多目标 DNS+游戏服务器）不抖动；
- **R2 粘滞与故障切换的张力**：会话粘滞会延迟故障切换（决策缓存不感知链路死亡）。处置：订阅 `ChainManager` 故障事件（现有 `handle_chain_failure`）主动失效受影响会话的决策缓存——记入实施清单，链路事件接口已存在；
- **O1 未决**：`client_id` 维度对无认证 socks5 退化为纯源地址，同 NAT 后多客户端会被合并会话——MVP 接受，文档标注。

## 2. SOCKS5 UDP ASSOCIATE 入站（P0-2）

### 2.1 复用

| 现有资产 | 用途 |
|---------|------|
| `seep-protocols::inbound::socks5` 整体框架 | `negotiate_method`/`perform_auth`/地址解析（ATYP 0x01/0x03/0x04）原样复用 |
| `IngressEndpoint` trait | `SocksInbound::run` 增加并行 UDP 监听分支，trait 不改 |
| `seep-core::UdpSessionTable`/`EgressUdpConnector`（§1） | 中继 socket 收包后走会话表 → 路由 → 出站 |
| `Credential` 认证 | `client_id` 粘滞键维度来源 |

### 2.2 新增

1. `parse_request` 接受 cmd `0x03`（UDP ASSOCIATE）：当前实现 `header[1] != 0x01 → send_error(0x07)`，改为 0x01/0x03 双分支（`inbound/socks5.rs` 第 226 行附近）；
2. UDP 中继 socket：**与 TCP 监听同端口号绑 UDP**（TCP/UDP 端口空间独立，客户端体验与 Clash 一致）；
3. ASSOCIATE 应答：`BND.ADDR/BND.PORT` 填中继 socket **实际绑定地址**——现有 `send_success` 回全零对 CONNECT 可行（流式无此语义），UDP 回零会导致客户端无处发包；
4. SOCKS5 UDP 请求头解析（`RSV(2) FRAG(1) ATYP(1) ADDR PORT`）：
   - `FRAG != 0`：MVP 拒绝（RFC 1928 允许不支持），回丢包计数指标（`reason="frag"`）——游戏流量实践上不分片，绕过组装复杂度；
   - 首包源校验：中继 socket 仅接受与控制连接**同源 IP** 的数据报（RFC 建议），配置项 `strict_udp_source`（默认 true）；
5. 下行方向：中继 socket 收到上游数据后按 SOCKS5 头封装发回客户端（复用会话表 `mappings` 反查客户端）。

### 2.3 与 TCP 面共存

同端口同进程：TCP listener 处理 CONNECT 控制流（现状不动），UDP socket 处理 ASSOCIATE 数据报；`ingress.socks5` 配置新增 `udp_enabled`（默认 **false**，开启后方启用，见 §5.2），未开启时 0x03 回 0x07 错误（与现状一致）。

### 2.4 验收标准（对齐 todo P0-2）

- 标准客户端经 socks5 入站 + direct 出站完成 DNS UDP 查询往返（如 `dig @8.8.8.8 example.com` over socks5 udp）；
- `seepctl stats` 可见 UDP 会话与字节数（依赖 §5 指标）；
- `udp_enabled=false` 时 0x03 请求收到 0x07 错误，TCP CONNECT 行为无回归（现有 socks5 测试全绿）。

### 2.5 风险与未决项

- **R3 BND 地址与多网卡**：多宿主机上中继 socket 绑 `0.0.0.0` 时回给客户端的 BND.ADDR 选择（回 0.0.0.0 客户端通常按控制连接对端 IP 处理，但存在兼容性差异）——实施时按 Clash/sing-box 惯例回 `0.0.0.0:实际端口`，出问题再引入 `advertise_addr` 配置；
- **R4 下行乱序/丢包**：中继单 socket 收发多上游，突发下行可能拥塞丢弃——处置：中继 socket 加 `recv` 缓冲与逐客户端公平轮转，记入实施清单；
- **O2 未决**：FRAG 分片在后续版本是否支持（视 TUN 阶段 DNS 大包场景需要）。

## 3. 出站 UDP 承载（P0-3）

### 3.0 通用机制

`seep-protocols::outbound` 新增 `udp.rs` 汇集四个 `EgressUdpConnector` 实现；构建期（`RuntimeBuilder`/seepd 启动）扫描 `routing` 可达出站类型：UDP 流量被路由到 **trojan/vless/socks5/http** 等无 UDP 能力类型时，**启动即报错并列出冲突节点名**（对齐 todo 验收"不支持的出站类型在构建期明确报错"）——不采用运行期静默丢包。现有 hy2/wg 出站已有 `TargetProto` 分派骨架（`Tcp => {}` + 兜底报错），UDP 分支直接落入同一 match。

### 3.1 direct（`outbound/direct.rs`）

- 复用：现有直连地址解析（`lookup_host`）、IPv4/IPv6 选择逻辑语义；
- 新增：`DirectUdpConnector`——每目标映射一个 `tokio::net::UdpSocket`（bind `0.0.0.0:0`，`connect(target)` 后收发），由 `UdpRelay` 句柄封装；
- 共存：与 TCP direct 完全独立，无共享 socket。

### 3.2 shadowsocks（`outbound/shadowsocks.rs`）

- 复用：workspace 依赖 `shadowsocks 1.21` **自带 UDP relay 能力**（`shadowsocks::relay::udp` 与 `ServerConfig`）——不手写 AEAD 包格式；现有 ss 出站的 method/password 配置结构（`EgressConfig::Shadowsocks`）；
- 新增：每包独立封装（crate 语义：`[salt][加密(目标地址+数据)]`，无连接概念，天然适配 NAT 式映射）；UDP over SS 不做流控，包长 ≤ 65507 由入站裁剪；
- 共存：TCP ss 连接池/隧道与 UDP 关联互不感知。

### 3.3 hysteria2（`outbound/hysteria2.rs`）

- 复用：现有 `Hysteria2Connector` 的 QUIC 连接建立、认证（`hysteria2` crate 0.1.6）、`TargetProto` match 骨架；
- 新增：hy2 协议 UDP 中继通道（QUIC 数据报语义，客户端请求 connect 后按 session id 收发数据报）——**依赖 crate 是否暴露 UDP API**；
- 共存：与 TCP 共用同一 QUIC 连接（协议设计如此），这是四个出站中唯一"TCP 面与 UDP 面共享底层连接"的，连接生命周期管理要防止 TCP 侧关闭连带断 UDP——记入实施清单；
- **未决项 V1（实施前置）**：核查 `hysteria2 0.1.6` 是否暴露 UDP relay API。若无：a) 升级 crate；b) 基于 quinn 自实现 hy2 UDP 通道；c) S1 暂缓 hy2 UDP、验收降级为 direct/ss/wg。**倾向 a→b**，验收以 todo P0-3 原文（hy2 必须可用）为目标。

### 3.4 wireguard（`outbound/wireguard.rs`）

- 复用：现有 `WireguardConnector` 的密钥/`allowed_ips`/接口配置（`defguard_wireguard_rs 0.8.0`），以及"目标 IP 必须落在 allowed_ips"的现有校验语义；
- 新增：UDP 承载 = 构造 IP 包写入 WG 接口再回收——新增**轻量 IPv4/IPv6 + UDP 头构造器**（源地址 = WG 接口地址，已有 `address` 配置字段）；解析收包方向同理剥头还原 `FlowTarget`；
- 共存：与 TCP over WG 共用同一 WG 接口与会话（WG 本身就是 L3，天然共轨）；
- 风险 **R5**：现有 WG 实现依赖系统 WG 接口（内核态/特权操作），UDP 版本不改变该前提——集成测试需特权环境，与 P1 TUN 测试环境需求重合，合并建设。

### 3.5 明确不在 S1 范围

- socks5 出站 UDP（PROTOCOLS.md 已声明，**状态：超前**）：协议支持但 S1 不做，构建期按"无 UDP 能力"报错；
- trojan UDP ASSOCIATE 扩展、vless/QUIC 承载：后续版本，PROTOCOLS.md 对应小节同步标注状态。

### 3.6 验收标准（对齐 todo P0-3）

- QUIC 站点（HTTP/3，如 `curl --http3`）分别经 **hy2 与 wg** 出站可访问；
- DNS UDP 查询经 ss 出站往返成功（AEAD 每包语义验证）；
- 将某 UDP 流量规则指向 trojan/vless 节点：seepd **启动报错**并指名冲突节点；
- direct 出站 UDP 有独立收发计数（§5）。

### 3.7 风险与未决项

- **R6 = V1**（hy2 crate 能力，见 §3.3）——S1 最大外部依赖风险；
- **R7 ss UDP 防滥用**：SS UDP 无认证握手语义（每包带地址），中继开放即成开放解析器风险——处置：默认仅允许路由规则命中的目标 + 会话表目标白名单化（映射只建在首包路由决策之后）；
- **R8 WG MTU**：WG 接口 MTU（配置默认 1420）内层 UDP 包超限会静默分片/丢弃——文档标注 MTU 预算，实测填入。

## 4. mesh 多跳 UDP envelope（P0-4）

### 4.1 复用

| 现有资产 | 用途 |
|---------|------|
| `MeshEnvelope` 的 path 剥离语义（`path[0]` 自剥 → 转发 `path[1]`） | UDP 跳行为完全同构 |
| `MeshRegistry`（节点寻址/角色/配额/ACL） | 下一跳解析与准入检查原样复用 |
| `MeshTlsConfig` 证书材质（`seepctl mtls` 产物） | §4.4 加密方案复用同一套 CA/节点证书 |
| `ChainManager` 链路构建/健康检查/`handle_chain_failure` | UDP 链路故障切换复用（§1.5 R2） |

### 4.2 新增：UdpEnvelope（二进制头）

TCP 面 envelope 是 JSON + 4 字节长度前缀（上限 64KB，见 mesh.md）——**UDP 面不能照搬**：单包必须落进 MTU（预算 ≤1200B 含业务载荷），JSON 头的体积与解析开销不可接受。因此 UDP 面从第一天起用紧凑二进制头：

```
magic(2)="SU" | ver(1) | flags(1) | flow_id(16, UUID bytes)
| atyp(1)+addr(4/16)+port(2)            # 最终目标
| path_mode(1)                           # 0=FULL 首包带全路径; 1=CACHED 后续包
| hop_index(1)
| [FULL: 节点数(1) + node_id 列表(len+bytes)]
| payload(...)
```

- **首包 FULL**：带全路径（与 TCP `MeshEnvelope` 的 path 语义对齐），每跳收到后缓存 `(flow_id → {next_hop, hop_index, expiry})` 并剥自身；
- **后续包 CACHED**：仅 `flow_id + hop_index`，各跳查缓存转发——游戏流量每秒数十包，路径只传一次；
- 跳缓存过期 = 会话过期（同 §1 超时），`flow_id` 碰撞概率可忽略（UUIDv4）；
- **与 P2-6 的关系**：P2-6（TCP 面 envelope 二进制化）直接采用本格式为统一协议 v2，TCP 面迁移时 UDP 面已是该格式——本节即 P2-6 的格式定义稿。

### 4.3 转发行为（`seep-runtime::mesh_transport` 扩展）

- `MeshDataPlane` 并行持有 TCP listener（现状）与 UDP socket（**同端口号**，TCP/UDP 双栈同端口，`MeshConfig.listen_address` 复用）；
- `MeshStream` trait 是 `AsyncRead+AsyncWrite`（TCP 专属），UDP 面用 `tokio::net::UdpSocket + §4.2 编解码` 直写，不强行抽象统一流接口；
- relay 节点：解 envelope → ACL/配额检查（复用 `MeshRegistry::check_quota`/`acl`）→ 查缓存/剥路径 → 发往下一跳；exit 节点：`connect_target` 现有函数语义的 UDP 版（新建 `udp_connect_target`）；
- 每 flow 有跳间会话过期（复用 §1 超时常量），relay 上 flow 缓存到期即清。

### 4.4 加密（与 TCP 面 mTLS 语义对齐）

TCP 面已实现"chain 启用时默认强制 mTLS、`SEEP_MESH_ALLOW_PLAINTEXT=1` 仅限开发"（mesh.md）。UDP 面按同等安全水位设计，三个候选：

| 方案 | 说明 | 评估 |
|------|------|------|
| A（推荐） | QUIC 数据报（`quinn` crate）+ 复用现有 rustls mTLS 材质 | 加密/防重放/无队头阻塞开箱即用，代价是新 workspace 依赖 |
| B | DTLS | Rust 生态无成熟维护栈，排除 |
| C | 每包 AEAD + 自管重放窗口，密钥从 mTLS 证书材质派生 | 零新依赖但自担密码工程风险 |

**MVP 兜底**：实施轮未定案前，UDP 面仅明文可用且由 `SEEP_MESH_UDP_ALLOW_PLAINTEXT=1` 显式开启（语义镜像 TCP 面），`chain+udp` 组合在未配置加密时拒绝启动。最终选型为**未决项 V2**，倾向 A。

### 4.5 与 TCP 面共存

- 同端口双栈、同 registry、同链路健康检查；TCP 面代码路径零改动；
- `RouteDecision::Chain` 对 UDP 流量同样由 `ChainManager` 升级产生（首包路由时），链路元数据（`seep.chain.path` annotation 语义）对 UDP 会话同样记录。

### 4.6 验收标准（对齐 todo P0-4）

- 两跳链路（client → relay → exit）UDP 双向转发：客户端经链路完成 DNS 查询往返；
- 对端不可达/会话空闲超时：relay 跳缓存与会话表条目按超时回收（断言内存回落 + 回收计数）；
- 首包 FULL/后续 CACHED 抓包验证：第 2 个包起不携带路径字段；
- `SEEP_MESH_UDP_ALLOW_PLAINTEXT` 未设且未配置加密时，`chain+udp` 拒绝启动（报错信息指明开关）。

### 4.7 风险与未决项

- **R9 = V2**（UDP 面加密选型，见 §4.4）；
- **R10 relay 跳缓存的内存上界**：每 flow 缓存很小但量大，需要全局 flow-cache 上限（默认 65536 条，LRU 驱逐 + 计数）；
- **O3 未决**：跨 relay 的 NAT 语义（relay 是否需要向上一跳回源校验）——MVP 依赖 envelope 的 flow_id 完整性 + 加密层认证，独立回源校验后置。

## 5. 观测与配置开关（P0-5）

### 5.1 复用

| 现有资产 | 用途 |
|---------|------|
| `SeepConfig` 顶层结构（`seep-config`） | 新增 `udp:` 区块，与 `control/telemetry/ingress/egress/routing` 平级 |
| `IngressConfig::Socks5`（tagged enum） | 变体新增 `udp_enabled` 字段，serde 向后兼容（缺省 false） |
| seepd 控制面 `/metrics` 手写 Prometheus 渲染（`apps/seepd/src/control_plane.rs`） | 追加 `seep_udp_*` 序列，与 `seep_mesh_link_bytes_total` 同一渲染路径 |
| `docs/grafana/seep-dashboard.json` | 追加 UDP 面板行 |

### 5.2 新增配置（示意，随实现定稿）

```yaml
udp:
  enabled: false                 # 全局总开关
  session_timeout_secs: 180      # §1.2
  mapping_idle_secs: 60
  max_sessions: 4096
  strict_udp_source: true        # §2.2
ingress:
  - type: socks5
    udp_enabled: true            # 覆盖全局开关（默认继承）
```

egress 无开关：UDP 能力由类型静态决定（direct/ss/hy2/wg 有，其余无），避免"配置说有运行时没有"的漂移。

### 5.3 新增指标

```
seep_udp_sessions_active            # 会话表当前大小
seep_udp_sessions_total             # 累计创建
seep_udp_bytes_total{direction=up|down}
seep_udp_packets_dropped_total{reason=timeout|frag|session_limit|no_mapping}
seep_udp_relay_handshake_errors_total   # mesh UDP 面（预留）
```

`/flows` 控制面接口同步区分 TCP/UDP 方向计数（现有累计流量结构加 proto 维度）。

### 5.4 与 TCP 面共存

同一 `/metrics` 端点、同一 `/flows` 快照、同一 Grafana dashboard 文件追加行；TCP 序列命名与语义不动。

### 5.5 验收标准（对齐 todo P0-5）

- `config/seep.yaml` 示例含 §5.2 区块且 `cargo` 校验通过（schema 往返：旧配置文件不含 `udp:` 仍可解析）；
- Grafana 面板可见 UDP 会话/字节/丢包序列（dashboard json 已更新）；
- `udp.enabled=false` 全链路无 UDP socket 监听（端口扫描验证）。

### 5.6 风险与未决项

- **R11 指标基数**：`per-target` 维度标签基数不可控，MVP 指标不带 target 标签（会话级聚合），per-link 细分属 P2-1；
- **O4 未决**：`/chains/stats` 是否为 UDP 链路单独分列——待 §4 实施时定。

## 6. 实施顺序与依赖

```
P0-1 会话表(trait+表+回收) ──► P0-2 socks5 入站 ──► P0-3 出站承载 ──► P0-4 mesh UDP ──► P0-5 观测贯穿
        │                                              ▲
        └────────── 构建期能力扫描（§3.0 报错机制依赖 P0-3 的类型清单）──────────┘
```

- P0-1/P0-2 可与 P0-3 并行开发（trait 先行，mock relay 单测）；
- P0-5 不是尾段：指标埋点随各步落地，dashboard 收口在最后；
- V1（hy2 crate 能力核查）是 P0-3 的第一张工单，其结论决定 P0-3 验收是否按原口径执行。

## 7. 风险与未决项汇总

| 编号 | 类型 | 内容 | 归属 |
|------|------|------|------|
| R1 | 风险 | 会话/映射 LRU 容量需压测确认 | §1 |
| R2 | 风险 | 粘滞缓存延迟故障切换 → 挂接 `handle_chain_failure` 失效缓存 | §1 |
| R3 | 风险 | 多网卡 BND.ADDR 兼容性，必要时加 `advertise_addr` | §2 |
| R4 | 风险 | 中继下行公平性与缓冲 | §2 |
| R5 | 风险 | WG 依赖特权接口，测试环境与 P1 TUN 合并建设 | §3.4 |
| R6/V1 | 未决 | `hysteria2` crate UDP API 能力核查（P0-3 第一工单） | §3.3 |
| R7 | 风险 | ss UDP 开放解析器风险 → 目标白名单化 | §3.2 |
| R8 | 风险 | WG MTU 预算标注 | §3.4 |
| R9/V2 | 未决 | mesh UDP 加密选型（倾向 quinn/QUIC + 复用 mTLS 材质） | §4.4 |
| R10 | 风险 | relay flow 缓存全局上界（默认 65536 LRU） | §4.3 |
| R11 | 风险 | 指标基数控制（MVP 无 target 标签） | §5 |
| O1 | 未决 | 无认证 socks5 下粘滞键退化 | §1 |
| O2 | 未决 | SOCKS5 FRAG 分片支持时机 | §2 |
| O3 | 未决 | relay 跳间回源校验 | §4 |
| O4 | 未决 | `/chains/stats` UDP 分列 | §5 |
