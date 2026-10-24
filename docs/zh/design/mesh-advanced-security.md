# P2-7 mesh 高级安全：CRL 分发 + UDP 面防重放 — 实现级设计

> 上游：[roadmap.md](roadmap.md) S4-4（「高级安全收尾：CRL/OCSP、mesh 端到端 MAC/防重放」）· [mesh.md](../mesh.md)「Security Notes」遗留 · [architecture.md](../architecture.md) 协作节点安全边界。
> 本文是落地定稿：**范围裁决、CRL 分发形态、UDP 帧防重放协议（v2 + 流序号 + 滑窗）、计数面、错误路径、测试策略、分步清单**。落地后偏差回填 §9。
> 复用基线：`MeshTls` 撤销文件 mtime 指纹热加载（`SEEP_MESH_MTLS_REVOKED_NODES[ _FILE]`，mesh_transport.rs）· `seepctl mtls revoke` 撤销列表文件管理（seepctl main.rs）· P0-4 UDP 面 `UdpEnvelope` 二进制帧（P2-6 已字节化：magic `SU` + version + flags + flow_id…）· `UdpFaceMetrics`/`UdpFaceSnapshot` 计数面（P0-5 §2.4）· control_plane (`Method, path)` 分派与 `/udp/stats` mesh 段（先例）。

## 0. 范围裁决

| 在本条目内 | 归 V2 / 其他 |
|-----------|-------------|
| 撤销分发**形态收口**：文件热加载已有的基础上，补充运行期可见性（控制面快照端点 + seepctl 查询）与文档口径 | OCSP/CA 直连拉取、CRL 自动下发推送（节点间除 mTLS 数据面外无 CA 通道；运维分发撤销文件 = 分发载体，见 D-2） |
|**UDP mesh 数据面防重放**：帧级流序号 + 接收方 64 位滑窗 + 重放丢弃计数（`replay_dropped`） | 端到端 MAC/认证（无端到端密钥分发机制——registry 无节点公钥、chain 无会话密钥协商；HMAC 无从挂靠，记 §9 偏差） |
| TCP mesh 数据面防重放姿态说明（mTLS 序号已防每跳重放；envelope 级端到端重放不可行的工程论证） | DTLS/QUIC 整体加密（udp-dataplane.md A 方案，V2 未决） |

**验收口径**（todo P2-7 原文两目，逐一兑现）：
1. 「撤销节点无需重启即可被拒」——**已具备**（文件 mtime 指纹热加载 + accept 时 `is_revoked`）；「**补 CRL 分发**」= 本条目 M0（分发状态运行期可见 —— 撤销列表载入/生效状态可查，配合既有文件载体构成「分发—生效—校验」闭环）；
2. 「**重放报文被丢弃并有计数**」= 本条目 M1（UDP 面滑窗丢弃 + `replay_dropped` 计数进入 `/udp/stats` mesh 段与 `/metrics`）。

## 1. 现状盘点（M0 前提）

- 撤销载体：`SEEP_MESH_MTLS_REVOKED_NODES`（CSV 静态）+ `SEEP_MESH_MTLS_REVOKED_NODES_FILE`（文件，mtime 指纹热加载）；TCP accept 时 `is_revoked(peer)` 拒连（mesh_transport.rs:1164）；
- 管理面：`seepctl mtls revoke add/list/remove`（原子写文件，main.rs）——**文件已是分发载体**（可共享文件系统/CI 下发/运维推送）；
- 缺口：**运行中节点「现已加载哪些撤销」不可观测**——运维无法确认分发已生效、「无需重启被拒」的可证性只存在于 is_revoked 的日志里，且无 counts/时间戳。M0 补观测面。

## 2. M0：CRL 分发形态收口（撤销快照端点）

### 2.1 `MeshTls::revoked_snapshot()`

```rust
pub struct RevokedSnapshot {
    /// 静态 env 条目（SEEP_MESH_MTLS_REVOKED_NODES）
    pub static_entries: Vec<NodeId>,
    /// 文件载体（None = 未配置 SEEP_MESH_MTLS_REVOKED_NODES_FILE）
    pub file: Option<RevokedFileState>,
}
pub struct RevokedFileState {
    pub path: String,
    pub loaded: bool,      // 载入失败时为 false（错误详情进 error）
    pub error: Option<String>,
    pub mtime_secs: u64,   // 最后载入版本的文件 mtime（epoch 秒）
    pub entries: Vec<NodeId>,
}
```

- 快照前 `maybe_reload()`（与 `is_revoked` 同口径——快照即当前生效面，不做第二状态）；
- 实现：`MeshTls` 内读 `cfg.revoked_node_ids` + `inner.revoked_node_ids` + `inner.fingerprint.revoked_mtime`；载入失败态（load 曾 Err）由 `load_revoked_nodes` 的上抛路径暴露——`MeshTlsInner::load` 现行 `?` 直接上抛会让 **maybe_reload 失败导致整连接面不可用**；M0 不改该语义（热加载失败的既有行为 = 连接被拒/报错，fail-closed 安全向），快照只呈现**最近成功载入**状态 + 静态条目。

### 2.2 控制面端点 `GET /mtls/revoked`

- 无 mesh/mTLS 装配（`get_mesh_plane` 缺省）→ `SERVICE_UNAVAILABLE`（`/nodes` 先例）；
- 响应 200：

```json
{
  "static_count": 2,
  "file": {"path": "/etc/seep/revoked.list", "loaded": true, "error": null,
           "mtime_secs": 1760000000, "count": 3, "entries": ["node-bad"]}
}
```

- 鉴权继承控制面现状（本机 HTTP，`x-admin-token` 若配置）。

### 2.3 `seepctl mtls revoke status [--endpoint]`

- 调 `GET {base}/mtls/revoked`；逐行渲染：`static: <count>`、`file: <path> (<loaded> mtime=<secs> entries=<count>)`、`  revoked: <node>` 逐条；
- 非 2xx → 现有 `控制面返回错误: {} - {}` bail 形（Chain 先例）。

### 2.4 运行结点无需重启即拒，闭环论证

`seepctl mtls revoke add file `（→ 原子写文件）→ 节点 mtime 指纹察觉 → 下一次 accept 前 `is_revoked` 命中 → 拒连。M0 的端点/CLI 使「分发已生效」可证：`seepctl mtls revoke status --endpoint` 显示新 mtime 新条目。

## 3. M1：UDP 帧防重放（v2 序号 + 滑窗）

### 3.1 动机与面择

- UDP 面无 TLS 序列保护（明文门或未来加密均为包级），**重放可注入陈旧/复制的业务载荷**（客户端重放「老钱包交易」，exit 侧无从分辨）；
- TCP 面 mTLS 序号已构成每跳防重放；「重放整条 TCP 连接」需先通过 mTLS 且被会话状态管理拒绝——**不作 envelope 级端到端重放**（重放失真的注入面只在包级无状态面）；
- 故防重放落 **UDP 面**，流级（flow_id 键），端到端语义（seq 由发送端生成、每一接收跳独立校验）。

### 3.2 帧格式：`UDP_ENVELOPE_VERSION = 2`（v1 兼容）

```
magic "SU" | version=2 | flags: bit0=dir, bit1=HAS_SEQ(=1) | flow_id(16)
| atyp | host | port | path_mode | hop_index | seq(4, BE, HAS_SEQ=1 时) | path? | payload
```

- **恒带 seq**：新帧 version=2 且 HAS_SEQ=1（编码无分支）；解码 v1 → `seq_present=false`；
- 保留位矩阵扩展：v1 维持 `flags & 0xFE != 0 → 拒`；v2 允许 bit1，其余保留位非 0 仍拒；
- `UdpEnvelope` 增字段 `seq: u32`、`seq_present: bool`（解码回填；编码 v2 恒置位）；
- **混布 fail-open（继承 R-obfs2 同版本部署假设）**：旧端发 v1（无 seq）→ 新端收：不校验（`seq_present=false` 跳过窗口）；新端发 v2 → 旧端解码拒帧（版本不符）→ **混布窗口新端→旧端方向数据面中断**，与 P0-4 明文门同口径：网格混布升级需窗口期（文档明示，跟 P1-4 pad 同门 §10）。

### 3.3 发送侧：per-flow 单调序号

| 发送点 | 序号源 | 说明 |
|-------|--------|------|
| client 桥 `MeshUdpRelay::send_to`（上行 FULL/CACHED） | 新字段 `next_seq: AtomicU32` | relay 单流单方向——fetch_add 即单调 |
| exit 下行 `exit_downlink_loop` | 新参数 `Arc<AtomicU32>`（建流时新建） | §13-1 生命周期随 ExitFlow |
| relay 转发 / relay 下行（一跳到下一跳） | **保留入帧 seq 原值** | 端到端语义：seq 是流级不是逐跳级；每接收跳独立窗口，乱序容忍一致 |

- seq 空间 2^32；wrap 处理：窗口比较用 wrapping 差（`(seq.wrapping_sub(last))` 判先后），2^31 半空间内单调——`u32::MAX` 流的 **40 亿包后** wrap，MVP 记 §10 限制（per-flow 生命周期远短于该量，见 R-replay）。

### 3.4 接收侧：64 位滑窗（RFC 4303 同款）

```rust
struct ReplayWindow { last: u32, bits: u64 }  // bit i = last - 1 - i 是否已收
```

判定（`seq_present` 时才走；wrapping 差 `diff = seq − last`，2^31 半空间内判先后）：
- `diff == 0` → 重放拒（last 恒拒）；
- `1 ≤ diff ≤ 64` → 前进接受；`last = seq`；`diff < 64` 时 `bits <<= diff`（历史右移），`diff == 64` 时历史清空（越 64 位窗）；
- `diff ≥ 65` 且 `< 半空间` → **前进超窗拒**（RFC 4303 同：跳窗帧与重放同判丢弃；攻击者 seq 跳变即丢，流级隔离见 §6 偏差 4）；
- `diff ≥ 半空间`（等价回退）→ `back = last − seq ≤ 63` 内查 bits 位：已置 → 重放拒；未置 → 接受置位；`back > 63` → 超窗拒（过旧）。
- 首包（窗口空）任意 seq 接受——窗口条目惰性创建（§7 R-replay2）。

键：**`(flow_id, dir)`**（流 + 方向；上下行各自窗口——exit 下行与 client 上行互不干扰）。无源节点 id 字段（帧不带），flow_id 是 128 位随机 UUID，跨流碰撞概率可忽略——与 P0-4 缓存同键前提。

### 3.5 存储与生命周期

- `UdpFace` 增 `replay: DashMap<([u8;16], u8), ReplayWindow>`（dir 编码 0/1）；
- **条目生命周期随 flow 缓存**：`sweep`/`retire_flow`/`forget_flow` 的 cache 条目消亡点一并 `replay.remove`（同 §13-1 三表回收语义，防窗口表无限增长）；
- 校验点在 `handle_udp_datagram`（decode 后、path 校验前）与 client 桥 `recv_from`（下行）——两处同函数 `replay_check(flow_id, dir, seq)`。

### 3.6 计数面

- `UdpFaceMetrics` 增 `replay_dropped: AtomicU64`（快照/渲染不变式：拒绝即计数，不混入 malformed/unknown_flow——新语义新计数）；
- `UdpFaceSnapshot` 增 `replay_dropped`；
- client 桥 `recv_from` 窗口拒 → `UdpClientMetrics` 增 `replay_dropped`（现 `dropped` 是广义丢弃、含解码错——重放单独可观测）；
- 观测渲染：`/udp/stats` mesh 段 `replay_dropped` + `mesh_client` 段 `replay_dropped`；`/metrics` `seep_udp_mesh_replay_dropped`（P0-5 §2.4 族追加）；
- seepctl `UdpMeshDto`/`UdpMeshClientDto` 增字段 `#[serde(default)]`（旧 seepd 对拷容错）。

### 3.7 错误路径

| # | 错误点 | 条件 | 语义 |
|---|--------|------|------|
| E1 | v2 编码 dir 位冲突 | HAS_SEQ 与 dir 同 bit（bit0 固定 dir） | 构造器缺陷（编码侧单分支恒位 0），不设处理 |
| E2 | v2 保留位非 0 | 解码 `flags & ~0x03 != 0` | malformed 丢弃 + 计数（扩 §13-3） |
| E3 | seq 段截断 | HAS_SEQ=1 但 <4 字节余量 | malformed 丢弃（udp_take 越界路径） |
| E4 | seq 超窗/重放 | 窗口判定拒 | **静默丢弃**（不 malformed——攻击或乱序都无需告知发送端）+ replay_dropped |
| E5 | v1 混布帧 | 解码 version=1 | 原样处理（不校验）——fail-open |

## 4. 测试策略

### 4.1 单测（无特权）

- **codec**：v2 带 seq 字节级 golden（seq 位置/大端）；v1 golden 回归（旧字节不变）；本文件既有矩阵扩 v2 保留位二态；seq 截断拒；
- **窗口**（纯函数，表驱动）：升序收、乱序收（窗口内未置位）、重放拒、超窗拒、跨窗跳跃收（bits 清零）、u32 wrap 前后各一（wrapping 差）；
- **计数**：replay 拒后 snapshot 的 replay_dropped 递增、malformed/unknown_flow 不动。

### 4.2 集成（真 socket，复用 §13 面往返先例）

- relay plane 往返（`udp_relay_plane`/`udp_exit_plane` 同类 fixture）：client 侧 v2 上行 → exit 收（forwarded_up=1）；**注入同 seq 重放帧** → exit 面 replay_dropped=1 且 exit 目标 socket 未收到重复 payload；
- 乱序帧（seq+1 先于 seq+0）→ 两包都到、窗口就位；
- client 桥下行重放：exit 下行帧重放 → client `recv_from` 拒继续循环、`replay_dropped` 递增。

### 4.3 端点/CLI（M0）

- `GET /mtls/revoked`：无 mesh → 503；装配态（env 静态 + 文件）→ 形状断言（count/entries/mtime）；
- seepctl 渲染纯函数 + 组装断言（不真发）。

## 5. 分步实施清单（R0–R4）

提交节奏循 P0-4 §9.1.1 铁律：每步 build/test 全绿 → 单 commit（引用本文 §节）→ fetch+rebase → push；禁 tag/force。

| 步 | 内容与落点 | 验收 |
|----|-----------|------|
| R0 | 本文设计稿 | — |
| R1 | M0：`RevokedSnapshot` + `get_mesh_plane` getter + `GET /mtls/revoked` + seepctl `mtls revoke status` | 4.3 全绿 |
| R2 | M1 codec+窗口：`UdpEnvelope.seq`/`seq_present` + v2 编解码 + `ReplayWindow` 纯函数 + `UdpFace.replay` 生命周期 | 4.1 全绿（golden + 窗口矩阵） |
| R3 | M1 接线+计数：发送侧三源序号、接收侧两校验点、`replay_dropped` 计数面（metrics/snapshot//udp/stats//metrics/seepctl） | 4.2 集成 + 既有 /udp/stats 断言更新 |
| R4 | 文档回填：mesh.md Security Notes、architecture.md 边界、todo P2-7 勾选 + 进度、`seepctl mtls revoke status` 帮助、§9 偏差 | 门禁全绿 |

## 6. 偏差与假设

| # | 类型 | 内容 |
|---|------|------|
| 1 | 范围 | **端到端 MAC/认证不在 MVP**：无端到端密钥分发机制（registry 无节点公钥、chain session 无密钥协商）。防重放 بدون认证的边界：窗口拒重放，但攻击者不能伪造新 seq 的语义（伪造需要 MAC）——重放攻击面被削平，伪造面归 V2（quinn/DTLS 或 chain 会话密钥 + HMAC）。todo/roadmap 措辞随本文回填，mesh.md 边界行同步 |
| 2 | 裁决 | **CRL 分发载体 = 文件**（共享文件系统/CI/运维下发，`seepctl mtls revoke add` 原子写）；「分发」的收口 = 运行期可观测（M0 端点/CLI）而非搭建拉取/推送通道（节点间无 CA 旁路通道，OCSP 需 CA 直连 = V2） |
| 3 | 假设 | 混布升级窗口 fail-open 继承（R-obfs2）：旧端发 v1 新端收不校验；新端 v2 → 旧端拒帧（版本门）——文档明示，P1-4 pad 同门（§10 R-obfs2 同版本部署假设） |
| 4 | 假设 | seq 空间 2^32 per (flow,dir)：60s idle TTL 生命周期内用量 ≪ 2^31 半空间（wrap 用 wrapping 差判定安全）；构造型超窗攻击（seq 跳 2^31）仅影响该流该方向窗口（bits 清零为已收集），流级隔离 |
| 5 | 偏差 | 热加载失败语义沿用既有 fail-closed（load Err → maybe_reload Err → 连接面报错）；快照呈现最近成功载入态，error 字段留诊断 |

## 7. 风险与未决

- **O-mix**：混布窗口 UDP 面新→旧方向中断（版本门）。缓解：文档明示 + 网格同版升级；与 P0-4 明文门/env 同批部署节奏；
- **R-replay2**：seq 校验在 decode 后、path 校验前——攻击者可对未命中窗口的帧（不存在的流）先建窗口条目？**裁决：窗口条目惰性创建**（校验通过的帧才 insert）——重放帧必先被真实首包拉出窗口，伪造流无窗口可污染；真实流首包 seq 混沌（非 0 起跳）拒后不建条目（窗口键仅在接受时入表）；
- **R-replay3**：多 client 同 next_hop 时 client 桥各自窗口——(flow_id, dir) 键天然隔离，无共享窗口需求。

## 9. 落地注记（R1–R4 偏差回填）

- **R1（fffc103）**：M0 按 §2 全量落地——`MeshTls::revoked_snapshot()`（快照前 `maybe_reload`，与 `is_revoked` 同口径）+ `GET /mtls/revoked`（无 mesh 503）+ seepctl `mtls revoke status --endpoint`（逐条渲染：static/file/revoked 列表）。帮助文本随 CLI 定义同轮落位。
- **R2（26e923d）**：M1 编解码+窗口按 §3.2/§3.4/§3.5 落地（v2 恒带 seq、`ReplayWindow` 纯函数、`UdpFace.replay` 惰性创建随 retire/forget/sweep 回收）。**措辞回填**：前进超窗（`diff ≥ 65`）与重放同判拒（RFC 4303 同——已入 §3.4 正文）；两向超窗均拒。
- **R3（7a8a209）**：M1 接线+计数按 §3.3/§3.6/§3.7 落地（发送侧三源序号、接收侧两校验点、`replay_dropped` 全观测链）。偏差：
  - **§4.2 集成测试形态**：注入帧直达 exit 属 FULL 上行，exit 侧缓存 `prev` 随之更新为注入端（§3 上行来源即下行回包目标——协议既定语义），故 later/middle 回包直回注入 socket 而不经 relay/client。测试改为从注入端读回包断言（payload 经 envelope 解码），「下行经 relay 抵 client」仅对经 relay 上行的帧断言（首包 ping 往返）；「每接收跳独立窗口」由 exit 计 2 / relay 计 0 / client 桥计 0 旁证；
  - **跨测试 env 全局竞态**：`RuntimeBuilder::build()` 的 enable_mesh 分支在 `SEEP_MESH_MTLS=1` 时**无条件**注入 `from_env_strict()`（runtime_builder.rs）——进程级 env 是测试间共享面，seepd 侧以 `MESH_MTLS_ENV_TEST_LOCK` 串行锁收编（`build_runtime` 全量持锁 + 两处 inline build+start 测试持锁），MeshConfig literal 显式 `data_plane_tls: None` 钉死；属测试基建收编，非产品代码变更。
- **验收兑现**：todo P2-7 两目——①「撤销节点无需重启即可被拒」：文件 mtime 热加载（既有）+ M0 生效面可证（R1）；②「重放报文被丢弃并有计数」：M1 滑窗拒 + `replay_dropped` 进 /udp/stats 与 /metrics（R2/R3）。端到端 MAC/认证不在验收两目内，归 V2（§6 偏差 1）。