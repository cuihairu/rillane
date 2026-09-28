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
- exit 侧 flow socket 空闲超时 = 缓存条目过期，由 §3 懒清扫统一回收（socket drop 即关闭）。

下行 dir=Down（relay 收到）：查缓存 → `send_to(cache.prev)`（不重写路径字段——CACHED 无路径）；未命中 → `unknown_flow` 丢弃。

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
- 与 TCP 面"chain 默认强制 mTLS"同水位；`env_flag` 复用 mesh_transport 现有助手。

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
