# P0-4 mesh data-plane UDP 转发 — 实现级设计

> 上游设计：[udp-dataplane.md](udp-dataplane.md) §4（P0-4 概念稿：envelope 格式/转发行为/加密三选一/验收）。
> 本文是实现级裁决：**精确格式、类型签名、状态机、接线点、测试计划**。落地后偏差回填 §11 与上游 §6 注记。
> 复用基线：P0-1 会话表（`seep-core::udp`）· P0-3 出站载荷（`EgressUdpConnector` + RoutingUdpConnector）· TCP 面数据平面（`seep-runtime::mesh_transport`）。

## 0. 范围

- 两跳链路（client → relay → exit）的 UDP 双向转发，首包 FULL / 后续 CACHED；
- UDP 面路由从基础 `RoutingEngine` 切到 `RuntimeFlowRouter`（chain 决策），链路故障复用 `ChainManager`；
- 加密按上游 §4.4 MVP 兜底：明文仅 `SEEP_MESH_UDP_ALLOW_PLAINTEXT=1` 显式开启，未配置加密时 chain+udp **构建期拒绝启动**（V2 quinn 选型未决，不在本条目）；
- 不含：QUIC 载荷（V2）、跨 relay 回源校验（O3）、TCP 面 envelope 二进制化（P2-6 用本文 §2 格式）。

## 1. 总览

```
client (MeshUdpRelay)          relay (MeshDataPlane UDP)        exit (MeshDataPlane UDP)
  │ UdpEnvelope FULL ──────────►│ 缓存 flow→{next,prev}          │ 缓存 flow→{next=None,prev}
  │      (path=[relay,exit])    │ 剥自身→FULL(path=[exit]) ─────►│ udp_connect_target
  │ UdpEnvelope CACHED ────────►│ 查缓存→CACHED ────────────────►│ → target
  │      (无路径字段)            │                                │
  │ ◄────────── CACHED(dir=down)│ ◄──── CACHED(dir=down) ────────│ target 回包→封 dir=down→prev
  ▼ 每节点一个共享 UDP 面 socket（转发+回包同源地址）；exit 的 target socket 每 flow 独立
```

- **socket 拓扑**：每节点 UDP 面一个共享 socket（同 TCP `listen_address` 端口，双栈同端口）；relay 的转发与回包都从它发出 → 对相邻跳而言来源地址稳定（NAT 友好，下行可回流）；exit 每 flow 一个 connected socket 发往真实目标。
- **无 TCP 化**：不经 `MeshStream` 抽象（上游 §4.3 已裁决）；编解码直写。
- **与 TCP 面的选择边界**（按传输协议在 ingress 分流，互不越界，全部基于既有分派点）：
  - TCP 连接（socks5 CONNECT 等）→ `Flow` → `FlowOutputRouter` → TCP 面 `MeshEnvelope`（JSON 头 + 4 字节 length 前缀，`mesh_transport.rs:165-172`/`write_envelope` 既有）——本条目零改动；
  - UDP 数据报 → P0-1 会话表 → `UdpChainRouter`（§5）→ UDP 面二进制 envelope（§2）；
  - QUIC 站点 = 普通 UDP（`TargetProto::Quic` 不特判）走 UDP 面；hy2 出站载荷（P0-3 §3.4(c) 移入）是**出口载体**问题，不经 mesh UDP 面；
  - 两面仅共享 `listen_address` 端口号与 registry/记账（`record_link_bytes`）；envelope 格式、socket、生命周期完全独立——TCP 面 flow 逐连接（`MeshStream` 双向拷贝、每连接 envelope 头一次），UDP 面 flow 逐数据报无连接（每包带 envelope 头）；
  - 加密水位差异（既有事实）：TCP 面 chain 默认强制 mTLS（`SEEP_MESH_ALLOW_PLAINTEXT` 仅 dev）；UDP 面 MVP 走 §6 明文门——V2 QUIC 载具时对齐。

## 2. UdpEnvelope 二进制格式（§4.2 精确化）

```
偏移  字段
0     magic(2) = 'S''U'
2     ver(1)   = 1
3     flags(1) : bit0 = dir（0=uplink, 1=downlink）；bit1..7 保留必须为 0
4     flow_id(16)  UUID 原始字节（uuid::Uuid::as_bytes，非字符串）
20    atyp(1)  : 1=IPv4, 4=IPv6, 3=domain
21    addr     : 4 / 16 / len(1)+bytes（domain ≤255）
…     port(2, BE)
…     path_mode(1) : 0=FULL, 1=CACHED
…     hop_index(1)
[FULL] hop_count(1) + node_id × hop_count（每项 len(1)+bytes）
…     payload(...)（上行=业务数据报；下行=目标回包）
```

```rust
pub enum UdpDir { Up, Down }
pub enum UdpPathMode { Full, Cached }
pub struct UdpEnvelope {
    pub version: u8,                    // 恒 1，其他值解码拒绝
    pub dir: UdpDir,
    pub flow_id: [u8; 16],
    pub target_host: String,            // domain/v4/v6 字符串化（exit 使用）
    pub target_port: u16,
    pub path_mode: UdpPathMode,
    pub hop_index: u8,
    pub path: Vec<NodeId>,              // Full 时非空；Cached 恒空（解码强制）
    pub payload: Vec<u8>,
}
pub fn encode_udp_envelope(env: &UdpEnvelope) -> Result<Vec<u8>>
pub fn decode_udp_envelope(buf: &[u8]) -> Result<UdpEnvelope>
```

- 校验：magic/ver/保留位/domain 长度/CACHED 携带路径（拒绝）；截断一律错误（计 `malformed`）。
- 与 P0-2 SOCKS5 头编解码同风格：纯函数、单测钉住（`seep-core/src/udp/associate.rs` 先例）。
- **落点**：`seep-runtime/src/mesh_transport.rs`（与 TCP `MeshEnvelope` 同文件；seep-mesh 不依赖 tokio 运行时细节，且转发行为同文件便于同测）。

## 3. 跳缓存（UdpFlowCache）

```rust
struct FlowCacheEntry {
    next_hop: Option<(NodeId, SocketAddr)>, // None = 本机为 exit
    prev: SocketAddr,                       // 上行来源（下行回送地址）—— §11-2 补充
    expiry: Instant,                        // last_touch + mapping_idle
}
struct UdpFlowCache {
    map: DashMap<[u8; 16], FlowCacheEntry>,
    ttl: Duration, max: usize,              // 默认 mapping_idle(60s) / 65536（R10）
}
```

- FULL 首包：`entry` 插入（已有同 flow_id → 刷新 prev/next 与 expiry，视为重关联）；CACHED：`get_mut` 触碰 expiry，未命中计 `unknown_flow` 丢弃。
- 上界（R10）：插入时若满 → 先扫除已过期；仍满 → 驱逐 **expiry 最早**者（同 TTL 下即最久未触 = LRU），驱逐计数 +1。O(n) 扫描可接受（条目小、量大但上界 65536）。
- 回收：serve 循环每秒懒清扫（移除过期，非独立任务，与 TCP 面解耦）。

## 4. relay / exit 转发行为（`MeshDataPlane` 扩展）

```rust
impl MeshDataPlane {
    /// 单数据报处理（serve_udp 调用；测试直调）
    pub async fn handle_udp_datagram(&self, sock: &Arc<UdpSocket>, from: SocketAddr, buf: &[u8])
        -> Result<()>;
    /// 同端口双栈 UDP serve（与 TCP spawn 共用 listen_address）
    pub fn spawn_udp(self: &Arc<Self>, bind: SocketAddr) -> JoinHandle<Result<()>>;
}
```

状态机（上行 dir=Up）：

1. decode → magic/ver/保留位校验失败：计 `malformed` 丢弃；
2. `env.path` 空 → 错误；`path[0] != local_node_id` → 错误（与 TCP 面同语义）；
3. **FULL**：校验本地角色 ∈ {Relay, Hybrid, Exit}；插入/刷新缓存；
   - `path.len() == 1`（本机即出口）：角色必须 ∈ {Exit, Hybrid}，转 exit 分支；
   - 否则 `next = path[1]`，registry 解析地址（角色不可为 Client），**剥自身**后整包重编码 `FULL(path=path[1..])` 发往 next——不做 CACHED 降级（每跳独立维护 FULL/CACHED 状态，与 TCP 面每跳重写 path 同构）；
4. **CACHED**：查缓存；命中且 `next_hop=None` → exit 分支；命中且 next 存在 → 原样（dir/payload）转发 next；未命中 → `unknown_flow` 丢弃。

exit 分支（上行到达出口）：

```rust
// 每 flow 独立 connected socket（复用 P0-3 LocalRelay 语义）
flows: DashMap<[u8;16], Arc<UdpSocket>>  // 空 ≙ 缓存 entry.next_hop == None
send(payload) → target；下行 task: socket.recv → UdpEnvelope{dir:Down, path_mode:Cached,
  flow_id, hop_index:0, payload} → send_to(cache.prev)
```

- 下行 task 与 P0-1 forwarder 同构：recv Err（target 不可达/复位）→ 清 flow socket + 缓存条目 + 计数；
- exit 侧 flow socket 空闲超时 = 缓存条目过期，由 §3 懒清扫统一回收（socket drop 即关闭）——**§13-1 修正**：下行 task 持 `Arc<UdpSocket>` 阻止 drop，回收改走 `retire_flow` 单点。

下行 dir=Down（relay 收到）：查缓存 → `send_to(cache.prev)`（不重写路径字段——CACHED 无 path 字段；**hop_index 仍每跳 +1 重编码**，见 §14-1）；未命中 → `unknown_flow` 丢弃。

## 5. 客户端出站：UdpChainRouter + MeshUdpRelay

```rust
// seep-runtime（私有）：P0-3 RoutingUdpConnector 的 chain 感知包装
struct UdpChainRouter {
    inner: RoutingUdpConnector,          // 非 chain 决策：按 final_node 分发（P0-3）
    mesh: Option<MeshUdpBridge>,         // chain 决策；None + chain 决策 → 构建期已拦截
}
#[async_trait]
impl EgressUdpConnector for UdpChainRouter {
    async fn associate(&self, ctx, decision) -> Result<Arc<dyn UdpRelay>> {
        match &decision.path {
            RoutePath::Chain { hops } if hops.len() >= 2 => self.mesh.as_ref()
                .ok_or_else(|| anyhow!("chain UDP 未启用"))?.associate(ctx, hops).await,
            _ => self.inner.associate(ctx, decision).await,
        }
    }
}

struct MeshUdpBridge { local_node_id: NodeId, registry: Arc<MeshRegistry>, cfg: MeshUdpGate }
// associate: next=hops[1] → registry.get_node_addr → 本地 UdpSocket bind ":0"
//            Arc<MeshUdpRelay>{ sock, next_addr, path: hops[1..].to_vec(), flow_id, target }
struct MeshUdpRelay { /* impl UdpRelay */
    // send_to: 首包 FULL(path=path, hop_index=0)，此后 CACHED（AtomicBool 已发 FULL；
    //          FULL 丢失的恢复：连续 unknown_flow 时客户端无从感知——MVP 依赖重关联：
    //          每 N=64 包或每 30s 重发一次 FULL 刷缓存，成本一个头）
    // recv_from: 解 CACHED(dir=Down) → (target, payload)；dir=Up 或 FULL → 丢弃计数
}
```

- `MeshUdpRelay` 直接实现 P0-1 `UdpRelay` trait → 会话表/§3.6 分级 teardown/forwarder 零改动复用；
- 角色：client 无 data-plane listener，只有出站 relay（§1 拓扑左列）。

## 6. 加密门（§4.4 V2 未决的 MVP 兜底）

```rust
pub struct MeshUdpGate { pub allow_plaintext: bool }  // env 只在 from_env 读取，测试显式传参
impl MeshUdpGate { fn ensure_usable(&self, tls: Option<&MeshTlsConfig>) -> Result<()> }
// tls 为 None 且 !allow_plaintext → Err("mesh UDP 面未配置加密且未显式允许明文
//   （SEEP_MESH_UDP_ALLOW_PLAINTEXT=1）；chain+udp 组合拒绝启动（udp-dataplane.md §4.4/V2）")
```

- **落点在构建期**（`RuntimeBuilder::build`）：非 client 角色拉起 UDP 面前、client 侧 UdpChainRouter::mesh 构建前各查一次；
- serve/associate 层不再重复检查（构建期拦截后路径必然合法）；
- 与 TCP 面"chain 默认强制 mTLS"同水位；`env_flag` 复用 mesh_transport 现有助手；
- gate 的配置合流点（`MeshConfig.udp_allow_plaintext_data_plane` ∪ env，P0-5 §1.5）定稿于 §13-6。

## 7. 记账与配额

- 跳间字节：每转发/收包对 `record_link_bytes(prev_or_local, next_or_local, bytes)`（对齐 TCP 面 dial/forward 语义；UDP 无连接，`record_link_connection` 仅 FULL 首包记一次）；
- 配额：exit 出向对 flow 首次出向字节走 `registry.check_quota(exit_node, bytes)`，Err → 丢弃 + 计数（不拆链）；
- 链路错误：connect next 失败 / exit connect_target 失败 → `record_link_error` 对（与 TCP 面同点位）。

## 8. 链路故障接线（P0-1 预留口径的落地）

- UDP 表路由器换成 `RuntimeFlowRouter`（chain 决策产生处）；粘滞决策缓存/ledger chain 绑定（P0-1 已建）原样生效；
- **chain_id 口径桥接**：`ChainManager.chain_id` 是 UUID 随机串，P0-1 `chain_id_of(decision)` 是 `chain:{hops.join("->")}`——两者不换算。`ChainFailureEvent` 由 runtime 在 `handle_chain_failure` 成功后构造：**chain_id 字段填 `chain_id_of(切换后的新决策)`**，failed_nodes 填旧链失败节点。ledger 绑定 gate（chain_id 相等才吊销）按新决策口径命中；
- 切换后本 UDP 面的流：决策已变 → 下包 ensure_decision 重路由（P0-1 语义），在途跳缓存自然过期。

## 9. RuntimeBuilder / seepd 接线

### 9.1 build() 阶段时序调整：UDP 块下移（本节为实施前提）

**现状（P0-3 落地后 `RuntimeBuilder::build()` 的阶段顺序）**：

| 阶段 | 内容 | 产物 |
|-----|------|------|
| ① | `validate()` + config snapshot + `RoutingEngine` 构造 | `router` |
| ② | **UDP 块**：`build_udp_connectors` → `scan_udp_capability` → `RoutingUdpConnector` → `UdpSessionTable`（FlowRouter = ① 的基础 engine）→ `UdpAssociateService` | `udp_service` |
| ③ | 入口/出口默认实现（`build_ingress_endpoints` 是 **udp_service 的唯一消费点**；egress 默认构建与之独立） | ingress_endpoints / flow_outputs |
| ④ | network_manager | – |
| ⑤ | mesh 配置完备化：mTLS env 强制、secure-by-default 明文检查、`register_local_mesh_node` | `local_node_id` / `mesh_registry` |
| ⑥ | `ChainManager` 初始化（依赖 ⑤ 的 registry） | `chain_manager` |
| ⑦ | `Ok(Runtime)` | – |

**冲突**：§5/§8 要求 UDP 表的 FlowRouter 换成 `RuntimeFlowRouter::new(engine, mesh_registry, chain_manager, local_node_id)`，其三个 mesh 参数是 ⑤/⑥ 的产物——而 UDP 块在 ② 已构造完成，时序倒挂。

**方案（裁决）：UDP 块整体下移到 ⑥ 之后**，新顺序 ①③④⑤⑥②′⑦；原 ② 位置留一行注释指向新位置。连带调整一处：`build_ingress_endpoints` 调用（udp_service 唯一消费点）随之顺延到 ②′ 之后。

**理由**：
- `UdpSessionTable::new` 的 FlowRouter 参数在构造即固化，且会话粘滞决策缓存、ledger chain 绑定都指向该实例——"早构造晚替换"不可行（换实例即丢运行期状态）；
- 备选方案"chain/mesh 块提前到 ② 之前"被否：⑤ 的 mTLS 强制与 secure-by-default 检查属于 mesh 配置完备化阶段，提前会改变 validate→build 的错误报告顺序（如 mTLS 缺失报错将先于 UDP 能力扫描报错出现），改动波及面大于 UDP 块自身下移；
- UDP 是可选面（udp.enabled=false 时 ②′ 直接跳过），下移不影响默认构建路径；
- `Runtime` 结构体字段与构造点不变（udp_service 在 ⑦ 前就绪）。

**影响面**：
- `runtime_builder.rs::build()` 内部块顺序调整；无函数签名变化、无 `Runtime` 字段变化；
- `build_ingress_endpoints` 调用点顺延（签名/参数不变）；
- `scan_udp_capability` 的报错时机随 ②′ 顺延到 mTLS/chain 检查之后——错误信息不变；
- 能力扫描等单测直调 helper 函数、不经过 `build()` 时序，零影响。

**验收口径**：
1. `udp.enabled=true + enable_chain=true`（mesh 配置齐全）：`build()` 成功，UDP 表持 `RuntimeFlowRouter`——chain 决策在 UDP 面可达（§10 #7 分派测试钉住，时序正确性由 Arc 所有权流转在编译期保证）；
2. `udp.enabled=true + enable_chain=false`：与 P0-3 行为等价（基础 engine 路由，非 chain 分派走 `RoutingUdpConnector`）；
3. `udp.enabled=false`：构建路径与本条目之前零差异；
4. 全仓测试基线（P0-3 时点 118 项）全绿。

#### 9.1.1 P0-4 分步实施清单（S0–S6，可执行）

**依赖顺序**：

```
S0 时序调整（纯重构）─┐
S1 UdpEnvelope 编解码 ─┼─► S3 MeshDataPlane UDP 面 ─┐
S2 UdpFlowCache 跳缓存 ─┘   S4 UdpChainRouter/MeshUdpRelay ─┴─► S5 接线 ─► S6 测试收口
（S1/S2 互相独立；S3 依赖 S1+S2；S4 只依赖 S1 的解码与 P0-3 trait；
 S5 依赖 S0+S3+S4；S6 依赖全部。每步独立可提交。）
```

**提交节奏**（沿用 P0-1..P0-3 铁律）：每步 = `cargo build` + `cargo test` 全绿 → 单条 commit（信息引用本文 §节）→ `git fetch origin main` + `git rebase origin/main` → push → 下一步；禁 tag / release / force push。全部完成后按 §10 勾选 todo.md。

**S0 build() 时序调整**（本节上文裁决的落地，纯重构）

- 落点：`runtime_builder.rs::build()`——UDP 块（`build_udp_connectors` → `scan_udp_capability` → `RoutingUdpConnector` → `UdpSessionTable` → `UdpAssociateService`）整体移至 `ChainManager` 初始化之后；`build_ingress_endpoints` 调用顺延；原位置留一行注释指向新位置。
- 依赖：无。
- 验收：`cargo build --workspace` 绿；`cargo test --workspace` 与 P0-3 基线（118 项）持平；diff 无 UDP 语义变化（此步 UDP 表的 FlowRouter 仍是基础 engine——换 RuntimeFlowRouter 属 S5）。

**S1 UdpEnvelope 编解码**（§2）

- 落点：`mesh_transport.rs`：`UdpDir` / `UdpPathMode` / `UdpEnvelope` + `encode_udp_envelope` / `decode_udp_envelope` 纯函数。
- 依赖：无。
- 实施要点：字段序与字节布局严格按 §2；`version != 1` / 保留位非 0 / domain 长度 >255 / CACHED 携带 path / 截断 → 一律解码错误。
- 验收：§10 T1 全绿（roundtrip × FULL/CACHED × v4/v6/domain × dir 两位，5 类拒绝各有断言）。

**S2 UdpFlowCache 跳缓存**（§3）

- 落点：`mesh_transport.rs`：`FlowCacheEntry` / `UdpFlowCache`（DashMap + ttl/max + 驱逐计数 + `sweep_expired`）。
- 依赖：无（与 S1 可并行使）。
- 实施要点：上界驱逐 = 满时先扫过期、仍满逐最早 expiry（§11-6）；条目 `expiry` 字段允许测试就地改写（同文件 `#[cfg(test)]` 可达私有字段，与现有 TCP 两跳测试同位），不引入时钟抽象。
- 验收：§10 T4（过期条目判 miss + `unknown_flow` 计数）、T5（max=2 插 3 → 最早 expiry 被逐 + 驱逐计数）、T8（`sweep_expired` 后 `len == 0`）全绿。

**S3 MeshDataPlane UDP 面**（§4 + §6）

- 落点：`mesh_transport.rs`：`MeshUdpGate::ensure_usable`；`MeshDataPlane` 增 `udp: Option<UdpFace>` 字段与 `with_udp(gate)` 构造子；`handle_udp_datagram` / `spawn_udp`；exit 分支的 per-flow connected socket 表 + 下行 task。
- 依赖：S1 + S2。
- 实施要点：转发/回包共用节点级 UDP 面 socket（§1 拓扑）；FULL→剥自身重编码、CACHED→查缓存转发（§11-4）；exit 下行从缓存读 prev（FULL 重刷新 prev 后下行随之改向）；gate 只做显式参数检查，env 读取留在调用方（§11-5）。
- 验收：§10 T6（tls=None 且 `!allow_plaintext` → Err 信息含 `SEEP_MESH_UDP_ALLOW_PLAINTEXT`）、T3（relay 直调 `handle_udp_datagram`，第 2 包 decode 为 Cached 且 path 空）、T4 的 unknown_flow 路径；单跳（client→exit）真 socket 往返先行钉住 exit 分支。

**S4 UdpChainRouter + MeshUdpRelay**（§5）

- 落点：`seep-runtime` 新私有模块 `udp_chain.rs`：`UdpChainRouter`（`RoutePath::Chain{hops≥2}` → mesh，其余 → 内部 `RoutingUdpConnector`）、`MeshUdpBridge::associate`（解析 hops[1] 地址 + 本地 socket）、`MeshUdpRelay`（impl P0-1 `UdpRelay`：FULL 首包 → CACHED 后续 + 周期重发 FULL，下行只认 CACHED dir=Down 且 flow_id 匹配）。
- 依赖：S1（解码）；P0-3 trait 面（已在仓库）。
- 验收：§10 T7（Chain 分派命中 MeshUdpRelay / Direct 落 inner 连接器）；`MeshUdpRelay` 对桩 UDP 对端（假 relay：收 FULL 存样、回 CACHED dir=Down）完成 send/recv 单测。

**S5 build() / seepd 接线**（§9.2 + §8）

- 落点：`runtime_builder.rs::build()`：udp.enabled && enable_chain 时 UDP 表 FlowRouter 换 `RuntimeFlowRouter`（S0 腾出的位置）；出站连接器换 `UdpChainRouter`；非 client 角色并列 `spawn_udp`（gate 前置）；`ChainFailureEvent` 按 §8 口径桥接。
- 依赖：S0 + S3 + S4。
- 验收：§9.1 验收口径 1–4 逐条核对（chain+udp build 成功且 chain 决策 UDP 可达 / 无 chain 等价 P0-3 / 关 udp 零差异 / 全仓基线绿）。

**S6 测试收口**（§10 全表）

- 落点：`mesh_transport.rs` / `udp_chain.rs` 的 `#[cfg(test)]` 模块（与现有 TCP 两跳测试同位，可达私有字段）。
- 依赖：S1–S5 全部。
- 验收：§10 T2 两跳真 socket 往返（client `MeshUdpRelay` → relay plane → exit plane → 环回 echo，dir=Down 全链路回包）；§10 八项全部在库且绿；`cargo build --workspace` + `cargo test --workspace` 绿 → todo.md P0-4 勾选（引用 §10 与本清单；hy2 验收项在勾选时按 V2 实情一并裁决）。

### 9.2 serve 与出站接线

- `build()`：udp.enabled 且 enable_chain 时，UDP 表的 `FlowRouter` 从基础 engine 换成 `RuntimeFlowRouter::new(engine, registry, chain_manager, local_id)`（经 9.1 时序调整后可行）；
- 出站连接器：`UdpChainRouter::new(RoutingUdpConnector, MeshUdpBridge::new(...))` 替换裸 RoutingUdpConnector（§3.1 能力扫描只针对非 chain 节点——chain 决策的 hop 是 mesh 节点，能力表扫描的 `mesh.` 豁免已就位）；
- mesh UDP 面 serve：现有 `plane.spawn(bind)` 旁并列 `Arc::clone(&plane).spawn_udp(bind)`（双栈同端口）；gate 检查（§6）先于两个 spawn；
- hy2 UDP（P0-3 移入的验收）仍不在本条目——载具是 quinn（V2），与 mesh UDP 解耦推进。

## 10. 测试计划（验收对齐 todo P0-4 / 上游 §4.6）

| # | 测试 | 钉住的验收 |
|---|------|-----------|
| 1 | 编解码 roundtrip：FULL/CACHED × v4/v6/domain × dir 两位；坏 magic/ver/保留位/截断/CACHED 带路径 → 拒绝 | §2 格式与校验 |
| 2 | 两跳真 socket 往返：client MeshUdpRelay → relay plane → exit plane → 环回 echo server；断言客户端收到回包（dir=down 全链路） | "两跳链路 UDP 双向转发" |
| 3 | FULL/CACHED 抓包断言：relay 直调 `handle_udp_datagram`，第 2 包 decode `path_mode=Cached` 且 path 空 | "第 2 个包起不携带路径字段" |
| 4 | 空闲过期：推进缓存条目 expiry 后 CACHED → unknown_flow 丢弃 + 计数 | "会话空闲超时按超时回收" |
| 5 | 上界驱逐：max=2 插 3 条 → 最早 expiry 被逐 + 驱逐计数 | R10 |
| 6 | 明文门：tls=None 且 allow_plaintext=false → `ensure_usable` Err 且信息含开关名 | "未配置加密拒绝启动" |
| 7 | UdpChainRouter 分派：Chain→MeshUdpRelay（注册表地址命中）/ Direct→inner 连接器 | §5 接线 |
| 8 | 内存回落断言：过期清扫后 cache len == 0（并入 #4） | "断言内存回落 + 回收计数" |

## 11. 与上游设计稿的偏差/补充（落地后回填 §6 注记）

| # | 上游 | 本文裁决 | 理由 |
|---|------|---------|------|
| 1 | §4.2 flags 未逐位定义 | bit0=dir（上行/下行） | 下行回流需要方向标记；CACHED 无路径字段，relay 无法凭包貌判向 |
| 2 | §4.2 缓存条目 `{next_hop, hop_index, expiry}` | 补 `prev: SocketAddr` | 双向转发的回流地址；UDP 无连接，无 prev 无法回送 |
| 3 | §4.2 flow_id "UUID bytes" | `[u8;16]` 原始字节为缓存键与线上格式 | 字符串化是 ×2.3 体积与解析开销，正是 §4.2 要避免的 |
| 4 | §4.3 "每跳收到后剥自身" | 每跳 FULL 重编码 `path[1..]`，不降级 CACHED | 与 TCP 面"每跳重写 path"同构；CACHED 判定留在各跳本地 |
| 5 | §4.4 MVP 兜底 "仅明文可用" | gate 落构建期；显式构造参数 + env 读取分离 | 测试不碰进程 env；拦截点单测可达 |
| 6 | §4.7 R10 "LRU 驱逐" | 同 TTL 下"最早 expiry = 最久未触"，O(n) 驱逐，无新依赖 | 语义即 LRU；避免引入 lru crate |
| 7 | §4.1 复用 "handle_chain_failure" | chain_id 口径桥接：事件填 `chain_id_of(新决策)` | ChainManager UUID 与 P0-1 口径不同构（P0-1 §9 注记 #7 预告） |

## 12. 风险与未决

- **V2**：QUIC/quinn 载荷选型（倾向 A）；落地时 UDP 面 socket 拓扑不变，仅传输层替换；
- **O3**：relay 回源校验后置（依赖加密层认证后重估）；
- FULL 周期重发（§5）的频率是拍脑袋值（64 包/30s），落地后按抓包调整——不计入验收。

## 13. 实施细节补全（第二轮复查，2026-09）

> 对本文第一轮定稿的缺口复查产物，补齐 S0–S6 实施所需的剩余细节；本节修正 §4、补充 §2/§6/§9.2，与前文冲突处以本节为准。同轮 P0-5 侧补全见 udp-observability.md §9。

### 13-1 exit 下行 task 生命周期（修正 §4）

§4 原表述"懒清扫统一回收（socket drop 即关闭）"有隐含缺陷：**下行 task 持有 `Arc<UdpSocket>`，只要 task 活着引用计数就不归零**——条目被清扫移除后 socket 仍开着、task 仍在 recv。修正：

- exit flow 表条目改为聚合条目：`flows: DashMap<[u8;16], ExitFlow>`，`ExitFlow { sock: Arc<UdpSocket>, task: JoinHandle<()> }`；
- 回收单点 `retire_flow(flow_id)`（对齐 P0-1 teardown 单点收敛先例）：`task.abort()` → `flows.remove(flow_id)` → `cache.remove(flow_id)`——三步顺序固定（先停 task 再拆两表，杜绝下行 task 向已删 prev 发包）；
- 三个触发点统一调它：① 懒清扫发现过期条目且本机为 exit（`next_hop==None`）→ 连带回收 flow；② 下行 task recv Err（target 不可达/复位）；③ FULL 重关联到**新 target**（旧 socket 对新 target 无意义，见 13-4）；
- task 自身 Err 退出路径：先 `flows.remove` 自身再返回（`abort` 对已完成 task 是无害 no-op，双保险不必需）。

### 13-2 `UdpFaceMetrics` 字段定稿（P0-5 §2.4 数据源）

```rust
pub struct UdpFaceMetrics {
    pub forwarded_up: AtomicU64,   // 上行转发数据报（含本机发出的 FULL/CACHED）
    pub forwarded_down: AtomicU64, // 下行回送数据报
    pub malformed: AtomicU64,      // 解码拒绝（§2 校验失败 + §13-3 超界）
    pub unknown_flow: AtomicU64,   // CACHED/下行未命中
    pub evicted: AtomicU64,        // 上界驱逐（R10）
    pub flows_active: AtomicI64,   // 缓存条目数（插 +/逐 −）
}
// 全 relaxed；get()/get_gauge() 拼装 Snapshot（对齐 P0-2 UdpIngressMetrics 形态）
```

- 落点：`mesh_transport.rs`，`UdpFace` 内持有；
- `seep_udp_mesh_flows_active` 直接读 gauge（不扫 `map.len()`——sweep 时点才有偏差，监控可接受）。

### 13-3 envelope 大小上界（补 §2）

- `encode_udp_envelope`：总长 > **65507**（IPv4 UDP 载荷理论上限）→ `Err`；调用方丢弃 + `malformed` 计数（正常路径 payload 不会超，此为防御性断言，兼挡路由前用户态塞超长包的误用）；
- decode 侧已有截断拒绝，不重复；
- mesh 面自身不分片：超出口 MTU 的以太网路径靠内核 IP 分片（direct/下一跳）；QUIC 载具（V2）自带自身分片。**MVP 约束**：业务 UDP 数据报 > 1400 字节时可靠性不承诺（游戏流量典型 ≤ MTU）——文档明示，不加配置项。

### 13-4 FULL 重关联与回收顺序

- 上行 FULL 命中已有条目（§3 已定：刷新 prev/next/expiry）**且 exit 侧 target 变化**（同 flow_id 新 target）→ 先 `retire_flow` 再按新 target 建流（13-1 ③）；
- relay 侧无 per-flow socket，重关联仅刷缓存；
- 顺序总则：**先 abort task，再移除 flow 表，最后移除缓存条目**（13-1 单点内部已固化）。

### 13-5 serve 层并发模型（补 §9.2）

- `spawn_udp` = 单任务循环：`recv_from → handle_udp_datagram` 顺序处理，**不 per-packet spawn**——每包处理无阻塞长操作（exit 首包 connect target 是唯一 await 点，冷启动串行可接受）；
- 高吞吐需求（V2）：`SO_REUSEPORT` 多 socket 分片（每 CPU 一个），`spawn_udp` 对外接口不变；
- exit 下行 task（per-flow recv）独立于 serve 循环，天然并发。

### 13-6 明文门配置合流（对齐 P0-5 §1.5）

gate 构造参数化（§6 已定 env 只在读取层出现）；**合流点定稿**：`RuntimeBuilder::build()` UDP 块内求值一次

```
allow_plaintext = cfg.mesh.udp_allow_plaintext_data_plane /* bool, serde default false */
                  || env_flag("SEEP_MESH_UDP_ALLOW_PLAINTEXT")
```

结果以 `MeshUdpGate { allow_plaintext: bool }` 显式传入两个消费点（非 client 的 `spawn_udp` 前 / client 的 `UdpChainRouter` mesh 臂构建前）——两处 gate 实例同源，测试传参即可覆盖两分支，不碰进程 env（§11-5 裁决不变）。

## 14. 多跳 TTL 与去重（第三轮补全）

> 缺口复查结论：§2 定义了 `hop_index` 字段但从未给语义；去重零覆盖。本节补齐——**全部基于既有字段与既有计数，不改线格式、不加新序列**。TTL/去重语义定义在 envelope 层而非 socket 层，V2 换 QUIC 载具（§12）时原样保留（quinn 连接自带的包号抗重放是另一层，互不替代）。

### 14-1 hop_index 语义与 TTL 上限

- 语义：**该数据报已穿越的跳数**——发送端置 0（上行 = 客户端 `MeshUdpRelay`；下行 = exit 下行 task，§4 已定 `hop_index:0`），**每经一个 relay +1**（与 FULL 剥自身 / CACHED 查缓存的转发点位同步，上/下行对称；下行的"+1 重编码"是对 §4 原文的补充修正，成本一次变长头重编码）；
- 上限 `MAX_UDP_HOPS = 16`（常量；mesh 链路深度实际受 ChainManager 构建约束，16 为远超正常拓扑的防御值）：relay 转发前校验 `hop_index >= MAX_UDP_HOPS` → 丢弃 + `malformed` 计数（复用 §13-2 既有字段）；客户端 `recv_from` 对下行同校验；
- **FULL 模式基本不需要 TTL**：path 每跳剥一个元素（TCP 面同构——`MeshEnvelope.path` 即 "Remaining path including the current node id as the first element"），环意味着 path 严格缩短至空或 `path[0] != local_node_id`，均被 §4-2 既有校验拒绝——FULL 环天然不可持续，hop_index 在 FULL 模式仅作观测/调试；
- **TTL 的真实作用面是 CACHED**：无路径字段，两个节点的跳缓存互指（陈旧状态/拓扑抖动/恶意构造）可能成环——`hop_index` 是 CACHED 模式唯一的环熔断器，这就是它存在于线格式的原因；
- exit 到达不做 hop_index 与 path 的对账校验（exit 只见剥剩的 path，无从对账原长）——上界熔断 + path 严格递减已闭环。

### 14-2 去重（duplicate suppression）裁决

- **不做载荷级去重**：UDP 语义本身允许重复递交（best-effort），QUIC/DNS/游戏协议在应用层自会处理；mesh 面引入 per-flow 序号/哈希窗口的代价（每跳状态、乱序误杀、跨跳不一致）大于收益——MVP 明确不做，此为裁决而非遗漏；
- **FULL 周期重发是"重复包"的唯一正常形态**：命中已有缓存 = 刷新条目（§3 已定），幂等无副作用，无需去重；
- **陈旧/错位包**：flow 已过期/驱逐 → CACHED 未命中 → `unknown_flow` 丢弃（既有）；flow_id 不匹配缓存键同理；
- **重放（恶意复制/延迟注入）**：MVP 明文门下无法认证来源，与 O3（relay 回源校验后置）同批归 V2——QUIC 载具连接自带 connection ID + packet number 抗重放，明文门 dev 场景不做；
- **环**：不靠去重挡——FULL 靠 path 校验（14-1），CACHED 靠 TTL 熔断（14-1）。
