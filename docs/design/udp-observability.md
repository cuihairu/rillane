# P0-5 UDP 观测与配置 — 实现级设计

> 上游设计：[udp-dataplane.md](udp-dataplane.md) §5（P0-5 概念稿：配置示意/指标草案/R11 基数风险/O4 未决）。
> **状态：已落地（todo P0-5 完成，2026-09）**——实施面 = `seep-core/src/udp/metrics.rs` + `seep-config` `udp:` 块 + `apps/seepd/src/control_plane.rs` 渲染与 `/udp/stats`；§10 S0–S6 分步清单已全部实施。
> 本文是落地定稿：**配置项清单、`/metrics` 命名与语义、seepctl 渲染、与 P0-4 数据面的衔接点**。
> 复用基线：P0-1 会话表指标（`TableMetrics`/`TableSnapshot`）· P0-2 ASSOCIATE 指标（`UdpIngressMetrics`）· P0-3 能力表 · P0-4 mesh UDP 面（`udp-mesh-dataplane.md`，**已落地**）。
>
> **2026-09-30 派工前置细化**：新增**分步实施清单 S0–S6（§10，每步含落点/依赖/交付/测试计划）**与**日志口径（§2.7）**；全文已对照 P0-4 落地实况与渲染/控制面现状复核，与初稿不符处以「落地核对」就地标出（§1.5/§2.1/§2.4/§2.5/§3.2/§4/§7/§9-1）。

## 0. 范围

- `seep-config` 的 `udp:` 区块补齐（P0-2 只暴露了 `UdpSessionConfig` 7 字段中的 3 个）；
- `/metrics` 增 `seep_udp_*` 全集（会话/关联/字节/丢弃/过期 + P0-4 mesh 面）；
- `seepctl stats` 增 UDP 段 + 新增 `seepctl udp-probe` 联调工具（收口 P0-2 遗留的"标准客户端联调"）；
- Grafana dashboard 追加 UDP 面板行；
- 日志口径收口（§2.7）：结构性事件 INFO / 单次路径错误 DEBUG / 高频事件只计数不打印，逐包路径零新增日志；
- 不含：per-target 指标维度（R11，归 P2-1）、UDP 面运行时热更新（§1.6 裁决为重启生效）。

## 1. 配置项清单

### 1.1 已有（P0-2 落地，语义不动）

`SeepConfig.udp`（`seep-config`）＝ `UdpConfig`：

| 字段 | 缺省 | 语义 |
|------|------|------|
| `enabled` | `false` | 总开关；false 时 socks5/mixed 对 CMD 0x03 回 0x07 |
| `strict_udp_source` | `true` | 数据报源 IP 校验（防中继借用） |
| `session_idle_secs` | `180` | 会话空闲上限 → `UdpSessionConfig.session_idle` |
| `mapping_idle_secs` | `60` | 目标映射空闲上限 → `mapping_idle`（P0-4 跳缓存 TTL 同源，§4） |
| `max_sessions` | `4096` | 全局并发会话上界（满员拒新） |

### 1.2 P0-5 新增：UdpConfig 补齐（映射 UdpSessionConfig 剩余字段）

| 新增字段 | 缺省 | → UdpSessionConfig | 约束（validate 复用现有检查） |
|---------|------|--------------------|------------------------------|
| `sweep_interval_secs` | `15` | `sweep_interval` | ≥1s（原实现允许 ms 级，配置面收紧到秒粒度） |
| `max_mappings` | `256` | `max_mappings` | ≥1（会话内映射上界，溢出逐最久空闲） |
| `session_lifetime_secs` | 无（不限） | `session_max_lifetime: Option` | ≥ session_idle_secs |
| `downlink_queue_depth` | `64` | `downlink_capacity` | ≥1（满即丢 + DownlinkFull 计数） |
| `max_associates` | `256` | （新：`UdpAssociateService` 并发 ASSOCIATE 上限） | ≥1；超限回 0x01 且 `associate_rejected` 计数（现实现仅并发门无上限，本项补防滥用） |

serde 全部 `#[serde(default)]` 向后兼容（旧配置缺字段可解析）。

### 1.3 ingress per-ingress 开关（上游 §5.2 `udp_enabled` 落地）

- `IngressConfig::Socks5` / `IngressConfig::Mixed` 各增 `#[serde(default)] pub udp_enabled: Option<bool>`：
  - `None`（缺省）→ 继承全局 `udp.enabled`；
  - `Some(false)` → 该入口显式关闭（ASSOCIATE 回 0x07），其余入口不受影响；
  - `Some(true)` → 显式开启（全局关时仅该入口可用，构建期警告提示全局开关语义）。
- 传递路径：`build_ingress_endpoints(descriptors, udp)` 已按入口构造——把"该入口是否拿 `Some(service)`"的判定从"全局 enabled"改为"per-ingress 覆盖 ∪ 全局"，服务实例仍全局共享一个（会话表/指标单例）。

### 1.4 egress：无开关（重申上游原则）

UDP 承载能力由出站类型静态决定（direct/shadowsocks/wireguard ✓；其余构建期报错，P0-3 §3.1 已钉）。不加 egress 配置开关，避免"配置说有、运行时没有"的漂移。wireguard MTU 已有节点级配置（`egress.wireguard.mtu`），不重复暴露。

### 1.5 mesh UDP 面配置（P0-4 衔接；落地核对：**已随 P0-4 S5 落地，P0-5 零新增配置**）

| 字段/来源 | 缺省 | 语义 |
|----------|------|------|
| env `SEEP_MESH_UDP_ALLOW_PLAINTEXT` | 未设 | P0-4 明文门（镜像 TCP 面 `SEEP_MESH_ALLOW_PLAINTEXT`）；chain+udp 未配加密时唯一放行途径 |
| `MeshConfig.udp_allow_plaintext_data_plane` | `false` | env 的持久化等价物（serde default false）；两者取或 |

**落地核对（2026-09-30）**：上表两行均已随 P0-4 S5 落地（commit 1d2d8af）——合流点 = `RuntimeBuilder::build()` 求值一次（`cfg.udp_allow_plaintext_data_plane ∪ env`），两消费点同源（client 桥构造期 + 非 client 面 start 期经 `Runtime.mesh_udp_gate` 副本）。**落点在 `crates/seep-runtime/src/runtime_builder.rs`（`MeshConfig` 定义于该文件，非 seep-config）**，§7 表已随之更正。P0-5 只做样例回填（S6：`config/seep.yaml` 明文门注释样例）与验收核验，不动该字段。

### 1.6 热更新语义与校验

- **UDP 配置变更重启生效**：订阅热更新管线不触碰运行期 `UdpSessionTable`/`UdpAssociateService` 参数（粘滞决策与会话状态不可热迁移）；存量会话按旧超时自然回收。文档与 `seepctl` 帮助文本明示。
- `UdpConfig::validate()` 新增字段约束随实现补齐（表内列），非法值构建期报错。

## 2. /metrics 指标命名与语义

### 2.1 渲染路径与约定

- 导出点：`apps/seepd/src/control_plane.rs::handle_metrics`。**落地核对：现有渲染助手只有两族**——`push_gauge`（无标签序列，TYPE gauge）与 `push_metric_header(name, help, "counter")` + `push_metric_labeled(name, labels, value)`（`seep_mesh_link_bytes_total` 即此法，control_plane.rs:339-373）；**不存在 `push_counter` 函数**（初稿笔误）。带标签的 direction/reason 序列 = header(counter) 后按封闭枚举成员逐条 labeled，序列集合静态可枚举；
- **恒渲染口径**：§2 全序列在 `/metrics` 恒存在（`udp.enabled=false` / mesh 面未启用时为 0），端点不因开关消失（§6-2）；
- 前缀统一 `seep_udp_`；counter 只增、进程重启归零（rate 语义交 Prometheus）；gauge 为瞬时值；
- **标签基数（R11 落地）**：仅 `direction`/`reason` 两个封闭枚举标签，无 target/host/用户标签（会话级聚合；per-link 细分归 P2-1）；
- 数据源均为原子量无锁读取：`TableMetrics` / `UdpIngressMetrics` /（P0-4）`UdpFaceMetrics`。

### 2.2 会话表序列（P0-1 基座 → 渲染）

| 序列 | 类型 | 数据源 | 语义 |
|------|------|--------|------|
| `seep_udp_sessions_active` | gauge | `TableMetrics.sessions_active` | 当前存活会话数 |
| `seep_udp_sessions_total` | counter | `TableMetrics.sessions_total` | 累计创建（含已回收） |
| `seep_udp_mappings_active` | gauge | `TableMetrics.mappings_active` | 当前存活目标映射数 |
| `seep_udp_reroutes_total` | counter | `TableMetrics.reroutes` | 粘滞决策重建次数（链路失效/缓存被清后） |
| `seep_udp_relay_bytes_total{direction="up\|down"}` | counter | **新增表级聚合**（§2.5） | 中继字节（客户端↔出口） |
| `seep_udp_relay_packets_total{direction="up\|down"}` | counter | `UdpIngressMetrics.uplink/downlink_packets` | 中继数据报数 |
| `seep_udp_dropped_total{reason=…}` | counter ×6 | `TableMetrics.dropped` | 丢弃；reason 封闭枚举 = `DropReason`：`session_limit`/`mapping_limit`/`no_binding`/`shutting_down`/`send_failed`/`downlink_full` |
| `seep_udp_expired_total{reason=…}` | counter ×3 | `TableMetrics.expired` | 回收；reason = `ExpireReason`：`idle`/`lifetime`/`revoked` |

### 2.3 ingress / ASSOCIATE 序列（P0-2 基座 → 渲染）

| 序列 | 类型 | 数据源 | 语义 |
|------|------|--------|------|
| `seep_udp_associates_active` | gauge | `UdpIngressMetrics.associates_active` | 当前 ASSOCIATE 控制连接数 |
| `seep_udp_associates_total` | counter | `associates_total` | 累计受理 ASSOCIATE |
| `seep_udp_associates_rejected_total` | counter | `associate_rejected` | 拒绝（并发门/上限，0x01 应答） |
| `seep_udp_associate_errors_total` | counter | `associate_errors` | 慢路径错误（关联/绑定失败） |
| `seep_udp_frag_dropped_total` | counter | `frag_dropped` | FRAG≠0 分片丢弃（不支持重组） |
| `seep_udp_source_dropped_total` | counter | `source_dropped` | 源地址不符（strict_udp_source） |
| `seep_udp_malformed_dropped_total` | counter | `malformed_dropped` | SOCKS5 头解析失败 |

### 2.4 mesh UDP 面序列（P0-4 衔接；命名收编上游预留）

上游 §5.3 预留名 `seep_udp_relay_handshake_errors_total` **废弃**：FULL/CACHED 协议无握手语义。错误按实际形态细分：

| 序列 | 类型 | 数据源（P0-4 `UdpFaceMetrics`） | 语义 |
|------|------|--------------------------------|------|
| `seep_udp_mesh_flows_active` | gauge | 跳缓存 len | 当前缓存 flow 条目（relay/exit 视角） |
| `seep_udp_mesh_forwarded_total{direction="up\|down"}` | counter | 转发计数 | 跳间转发数据报 |
| `seep_udp_mesh_unknown_flow_total` | counter | unknown_flow | CACHED 未命中（含过期后到达） |
| `seep_udp_mesh_malformed_total` | counter | malformed | envelope 解码失败 |
| `seep_udp_mesh_evicted_total` | counter | 驱逐计数 | 上界驱逐（R10） |
| `seep_udp_mesh_client_dropped_total` | counter | **新增 `UdpClientMetrics.dropped`**（P0-4 `MeshUdpRelay.dropped` 的进程级收编） | client 出站侧下行丢弃（dir=Up / FULL / flow_id 不符 / 解码失败——`recv_from` 过滤点） |

**client 侧 `dropped` 的收编裁决（落地核对后新增）**：P0-4 将该计数落在 per-relay 的 `AtomicU64`（`udp_chain.rs`，标注「读取点 = P0-5」），per-flow 实例无法聚合。收编为进程级：`MeshUdpBridge::new` 构造 `Arc<UdpClientMetrics>{dropped: AtomicU64}`，`associate` 把**同一 Arc** 传入各 `MeshUdpRelay`（字段从 `AtomicU64` 换 `Arc<UdpClientMetrics>`，fetch_add 点不变）；`RuntimeBuilder::build()` 在包装 `UdpChainRouter` 前抽出该 Arc 存 Runtime 字段（观测 getter）。面（服务端视角）与 client（发起端视角）两个序列分立，client 侧不混入 `seep_udp_mesh_*` 面族——命名/语义与 §0.2「分族不混算」一致。

### 2.5 字节聚合的实现裁决

现状字节计数只在 per-mapping（`MappingShared.bytes_up/bytes_down`）。`/metrics` 抓取若扫描全表聚合为 O(活跃会话)，scrape 开销随负载波动。**裁决**：`TableMetrics` 增全局 `bytes_up`/`bytes_down` AtomicU64，在既有计数点（`count_up`/`count_down` 调用处）顺带累加——渲染零扫描；per-mapping 数值保留给 `SessionSnapshot`（seepctl/stats 详单用）。

**落地核对（调用点全仓仅两处）**：`table.rs:369`（上行，表方法内 `self.metrics` 直达）与 `table.rs:608`（下行 forwarder，构造时已持 `Arc::clone(&self.table.metrics)`，见 table.rs:538）——两处上下文对 `TableMetrics` 均已可达，零新穿透、零新锁。

### 2.6 /flows 与 /chains/stats 的裁决（关闭上游 O4）

- **`/flows` 不加 proto 维度**：UDP 会话不经过 `FlowOutputRouter`（P0-2 起 UDP 面直接进会话表，无 FlowStatItem）；硬拼两套统计模型只会产生语义含混的双口径。UDP 观测口径 = 本文 `seep_udp_*` + `seepctl stats` UDP 段（§3）。
- **`/chains/stats` 不为 UDP 分列**（关闭 O4）：链路维度的 UDP 流量已经由 P0-4 `record_link_bytes` 进入 mesh per-link 序列（`seep_mesh_link_bytes_total`，现成），重复分列无增量信息。

### 2.7 日志口径（tracing；与计数器分工）

现状核对：UDP 相关既有 target = `seep::socks5_udp`（`associate.rs`：INFO ASSOCIATE 建立/结束、DEBUG slow_path 错误与下行发送失败）、`seep::socks5`/`seep::mixed`（入口启动 INFO、连接处理失败 WARN）、`seep::mesh::transport`（mesh TCP/UDP 面：DEBUG 数据报丢弃与连接关闭）。P0-5 遵循同一分工并收口如下：

| 事件 | 载体 | 等级 / target |
|------|------|--------------|
| ASSOCIATE 建立/结束、入口启动 | 既有日志（不动） | INFO，`seep::socks5_udp` / `seep::socks5` / `seep::mixed` |
| slow_path 错误、下行发送失败、mesh 数据报丢弃 | 既有日志（不动） | DEBUG，`seep::socks5_udp` / `seep::mesh::transport` |
| per-ingress `Some(true)` 且全局关 | 构建期一次性提示（新） | WARN，`seep::boot` |
| `max_associates` 拒新 | 仅计数 `associate_rejected` + 既有 0x01 应答路径（**不新增打印**） | — |
| 会话/映射回收 sweep、mesh flow 建/回收（retire/forget） | **只计数不打日志**（`expired`/`flows_active`/`unknown_flow` 承载；flow 生命周期秒级，逐条打印无增量信息） | — |
| 逐包成功 / 逐包丢弃 | **禁止新增**（forwarded/dropped/unknown_flow/malformed 全部计数器承载；唯一既有例外 = mesh serve 循环丢弃 DEBUG 一条，保留不动） | — |
| `udp-probe` 输出 | CLI stdout/stderr（§9-3 退出码表），不走 tracing | — |

配置校验失败（validate）走 anyhow 构建期 bail（既有机制），不入 tracing。总原则：**高频事件一律计数器，日志只承载结构性事件与一次性错误**——本任务不新增任何逐包日志路径。

## 3. seepctl：stats UDP 段 + udp-probe 联调工具

### 3.1 控制面快照端点 `/udp/stats`（新增）

control_plane 暴露 JSON：`{ table: TableSnapshot, ingress: UdpIngressMetricsSnapshot, mesh: Option<UdpFaceMetricsSnapshot> }`（快照结构均为既有 `get()`/`get_gauge()` 拼装，无新状态）。

### 3.2 `seepctl stats` 渲染

**落地核对**：现 `seepctl stats` 打 `/flows`（默认 `http://{control.api_bind}/flows`，`--endpoint` 覆盖；解析 `Vec<FlowStatItem>`——seepctl `Command::Stats` 处理段）。改造：默认模式下先按现样打 `/flows` 表，随后 GET 同 base 的 `/udp/stats`（§3.1）追加渲染 UDP 段（§9-2 样式）：sessions/mappings active·total、dropped×6、expired×3、bytes/packets up·down、associates active·rejected、mesh 段（P0-4 启用时）。`--endpoint` 覆盖仅作用于 `/flows` 一侧（UDP 段仍从同 base 推导）；`/udp/stats` 不可达/404 时 UDP 段打印 `(控制面无 UDP 段)` 且不视为失败（对旧版 seepd 兼容）。

### 3.3 `seepctl udp-probe`（收口 P0-2 "标准 CLI 联调"遗留）

curl/dig 均不支持 SOCKS5 UDP ASSOCIATE（curl 走 TCP、dig 无代理面），proxychains 依赖系统栈不可控。**裁决**：内置最小 RFC 1928 ASSOCIATE 客户端：

```
seepctl udp-probe --socks5 127.0.0.1:1080 --host example.com --port 53 \
                  --payload-hex <DNS 查询hex> [--timeout 3s] [--user u --pass p]
```

流程：TCP ASSOCIATE → 收 BND → 按 §7 头封装目标发查询 → 等回包（解头打印源与载荷长度）→ EOF 撤销。退出码 0=往返成功。作为验收工具直接可执行（不引入新依赖，seepctl 已有 tokio）。

**实现落点**：核心逻辑（协商 / ASSOCIATE / 头封装 / 收包 / RTT 计时）提为 `apps/seepctl/src/udp_probe.rs` 独立模块（seepctl 现为单文件 `main.rs`，本任务拆出此一个模块），函数签名收 `&str`/`Duration`/socket 参数——集成测试直调同一函数（S5 测试计划），`main.rs` 只做 clap 接线与退出码映射（§9-3）。

## 4. 与 P0-4 数据面的衔接点（汇总）

| 衔接点 | P0-5 侧 | P0-4 侧（udp-mesh-dataplane.md） |
|--------|---------|--------------------------------|
| 指标·面族 | §2.4 前五序列渲染 | `UdpFaceMetrics` 原子量 + `UdpFlowCache::{unknown_flow,evicted}`（收编进快照） |
| 指标·client 侧 | §2.4 `seep_udp_mesh_client_dropped_total` | `MeshUdpRelay.dropped` → `UdpClientMetrics` 进程级收编（§2.4 裁决） |
| 配置·明文门 | §1.5（**已落地**，样例回填归 S6） | `MeshUdpGate::ensure_usable` 消费（合流点 build()） |
| 配置·超时同源 | `UdpConfig.mapping_idle_secs` 单一事实来源 | 跳缓存 TTL = mapping_idle（P0-4 §3，S5 经 `with_udp_limits` 接线） |
| 快照 | `/udp/stats` 的 `mesh` 段 | `UdpFaceSnapshot`（**P0-5 新增**：P0-4 落地时未建快照面） |
| 可达性接缝 | 控制面经 `Runtime` 取数 | **Runtime 持有路径为 P0-5 补齐**：① `get_udp_service()`（`Runtime.udp` 字段已存在但无 getter）；② `mesh_plane: OnceLock<Arc<MeshDataPlane>>`——P0-4 现 plane 的 Arc 只活在 start() 局部与 spawn 任务里，观测不可达，S3 在 `spawn_udp` 后回填；③ `udp_client_metrics`——build() 包装 `UdpChainRouter` 前从 bridge 抽出 |
| 链路字节 | 不另设序列（§2.6） | `record_link_bytes` → 既有 `seep_mesh_link_bytes_total` |
| 验收分层 | 渲染/端点测试（P0-5 §10 各步） | 转发行为测试（P0-4 §10）互不覆盖 |

## 5. Grafana 面板（docs/grafana/seep-dashboard.json 追加）

行 1「UDP 会话」：`seep_udp_sessions_active`、`seep_udp_associates_active`、`seep_udp_mappings_active`；
行 2「UDP 流量」：`rate(seep_udp_relay_bytes_total[1m])` by direction、`rate(seep_udp_relay_packets_total[1m])`；
行 3「UDP 质量」：`rate(seep_udp_dropped_total[1m])` by reason、`rate(seep_udp_expired_total[1m])` by reason、`seep_udp_reroutes_total` 增量；
行 4「mesh UDP」（P0-4 启用时）：`seep_udp_mesh_flows_active`、`rate(seep_udp_mesh_unknown_flow_total[1m])`、`rate(seep_udp_mesh_forwarded_total[1m])`、`rate(seep_udp_mesh_client_dropped_total[1m])`（client 视角，§2.4）。

## 6. 验收对齐（上游 §5.5 + P0-2 遗留）

1. 示例配置含 §1 UDP 区块（`examples/` 或 `config/` 样例更新）；schema 往返测试：不含 `udp:` 的旧配置可解析（serde default 钉住）；
2. `/metrics` 含 §2 全序列；类型/HELP 齐全；`udp.enabled=false` 时序列存在但为 0（gauge 0/counter 0——端点不因开关消失，抓取侧无需分支）；
3. Grafana 面板可见 UDP 序列（dashboard json 更新入库）；
4. `udp.enabled=false` 全链路无 UDP socket 监听（构建断言：UdpAssociateService 为 None；集成验收端口扫描）；
5. `seepctl stats` 显示 UDP 段；
6. `seepctl udp-probe` 经 socks5 入站 → 会话表 → direct 出站完成 DNS 查询往返（全链路联调，收口 P0-2 遗留）；
7. 配置项全部过 validate（非法值构建期报错）。

## 7. 实施落点（文件清单）

| 文件 | 内容 |
|------|------|
| `crates/seep-config` | `UdpConfig` 补 5 字段 + validate；`IngressConfig::{Socks5,Mixed}` 增 `udp_enabled: Option<bool>`；`resolve_udp_enabled` 纯函数。（~~MeshConfig 增字段~~——落地核对：已随 P0-4 S5 落地于 seep-runtime，本任务不动，§1.5） |
| `crates/seep-core/src/udp/metrics.rs` | `TableMetrics` 增 `bytes_up/bytes_down`；`TableSnapshot` 增 bytes；`UdpIngressSnapshot` 新结构 |
| `crates/seep-core/src/udp/table.rs` | 369/608 两处既有计数点顺带累加表级字节（§2.5 落地核对） |
| `crates/seep-core/src/udp/associate.rs` | `max_associates` 上限（`try_register_associate` 总量门）；snapshot 拼装 |
| `crates/seep-runtime/src/runtime_builder.rs` | per-ingress udp_enabled 判定（`build_ingress_endpoints` 增参）；新配置字段映射（提纯函数 `udp_session_config(&UdpConfig)`）；`Runtime` 增 `get_udp_service()` / `mesh_plane: OnceLock<..>` / `udp_client_metrics` 三观测接缝（§4） |
| `crates/seep-runtime/src/mesh_transport.rs` | `UdpFaceSnapshot` pub 结构 + `UdpFace::snapshot()`（合并 metrics 四值与 cache 两计数）+ `MeshDataPlane::udp_snapshot()` |
| `crates/seep-runtime/src/udp_chain.rs` | `UdpClientMetrics{dropped}` 收编（`MeshUdpRelay` 字段换共享 Arc，§2.4 裁决） |
| `apps/seepd/src/control_plane.rs` | `/metrics` UDP 序列渲染（`push_gauge` / `push_metric_header`+`push_metric_labeled`，§2.1 落地核对）；`/udp/stats` 端点 |
| `apps/seepd/src/control_plane.rs`（P1-2 届时） | `seep_tun_*` 序列渲染（定义见 [tun-dataplane.md](tun-dataplane.md) §2.8；本条目不含，见 §9-5） |
| `apps/seepctl/src/main.rs` + 新 `apps/seepctl/src/udp_probe.rs` | stats UDP 段；`udp-probe` 子命令（核心逻辑库化于 `udp_probe.rs`，§3.3） |
| `docs/grafana/seep-dashboard.json` | §5 四行面板 |
| `config/seep.yaml` | `udp:` 注释样例区块 + mesh 明文门注释样例（落地核对：仓库样例即此文件，无 examples/ 目录） |

## 8. 风险与未决

- **R11（重申）**：无 target/host/用户标签；若 P2-1 需要 per-link UDP 细分，届时以 cardinality 预算另立序列，不改本文封闭枚举；
- `seep_udp_relay_bytes_total` 的表级聚合在并发下为 relaxed 累加，与 per-mapping 快照可能有瞬时微小偏差（监控用途可接受）；
- `udp-probe` 的 DNS 载荷由调用方给 hex（不做 DNS 编码器），保持工具最小面。

## 9. 实施细节补全（第二轮复查，2026-09）

> 与 P0-4 §13 同轮的缺口复查产物；P1-2（tun-dataplane.md）落地后的跨稿衔接一并收口。字段名已对照 P0-2 实现（`UdpIngressMetrics`，`seep-core/src/udp/associate.rs:106`）核实。

### 9-1 `/udp/stats` 响应示例（§3.1 精确化）

`ingress` 段字段即 `UdpIngressMetrics` 原子量既有名（P0-2 已钉，勿改名）；`table` 段以 `TableSnapshot` 实现字段为准（P0-1），示例按指标同名列出；`mesh` 段 = P0-4 §13-2 定稿：

```json
{
  "table": {
    "sessions_active": 3, "sessions_total": 128, "mappings_active": 7,
    "reroutes": 2, "bytes_up": 1048576, "bytes_down": 2097152,
    "dropped": {"session_limit": 0, "mapping_limit": 0, "no_binding": 0,
                "shutting_down": 0, "send_failed": 1, "downlink_full": 0},
    "expired": {"idle": 120, "lifetime": 0, "revoked": 1}
  },
  "ingress": {
    "associates_active": 3, "associates_total": 45, "associate_rejected": 2,
    "associate_errors": 0, "uplink_packets": 1024, "downlink_packets": 980,
    "frag_dropped": 0, "source_dropped": 0, "malformed_dropped": 0
  },
  "mesh": {
    "forwarded_up": 512, "forwarded_down": 480, "malformed": 0,
    "unknown_flow": 3, "evicted": 0, "flows_active": 4
  },
  "mesh_client": {"dropped": 0}
}
```

（`mesh` 段仅 P0-4 面启用时为对象、否则 `null`——面未启用与零流量两态可区分；`mesh_client` 段仅 client 侧出站装配（chain+udp）时出现，未装配省略该键（§2.4 收编裁决）；`table`/`ingress` 段恒在（UDP 关闭时全零，§6-2）；数字为示意。）

### 9-2 `seepctl stats` UDP 段渲染样式（§3.2 精确化）

```
UDP:
  sessions    3 active / 128 total (mappings 7 active)
  relay       1.0 MiB up / 2.0 MiB down (1024 / 980 packets)
  associates  3 active / 45 total (2 rejected)
  dropped     send_failed=1
  expired     idle=120 revoked=1
  mesh        512 up / 480 down (flows 4, unknown_flow 3)   ← P0-4 启用时
```

零值行照打（与 §6-2 "序列不因开关消失"同口径，渲染侧无需分支）。

### 9-3 `udp-probe` 退出码（§3.3 补全）

| 码 | 含义 | stderr 附带 |
|----|------|------------|
| 0 | 往返成功（收到回包并解头） | 源地址与载荷长度 |
| 1 | TCP 连接 / SOCKS5 握手 / 认证失败 | 阶段与 IO 错误 |
| 2 | ASSOCIATE 被拒（REP 0x01/0x07） | REP 码与语义（0x07 = 入口未开 UDP） |
| 3 | 超时无回包（`--timeout`，默认 3s） | 已发出字节数 |
| 4 | 回包包头解析失败 | 解码错误 |

非 0 即失败，便于脚本化钉验收 #6。

### 9-4 per-ingress `udp_enabled` 判定伪码（§1.3 钉死）

```rust
fn resolve_udp_enabled(global_enabled: bool, per_ingress: Option<bool>) -> bool {
    per_ingress.unwrap_or(global_enabled)
}
```

- 求值点：`build_ingress_endpoints` 逐入口调一次（`UdpAssociateService` 实例仍全局单例，§1.3）；
- `Some(true)` 且全局关 → 构建期 warning（§1.3 语义）；
- 测试三行钉住三态：None 继承 / Some(false) 关 / Some(true) 开。

### 9-5 跨稿衔接：`seep_tun_*`（P1-2）

tun-dataplane.md §2.8 的 `seep_tun_*` 家族渲染走本文同一渲染管线（§2.1 落地核对后的 `push_gauge` / `push_metric_header`+`push_metric_labeled`），**不新开端点/机制**；§7 清单已增 P1-2 衔接行。P0-5 实施时不渲染该家族（序列未定义时跳过），P1-2 T5 落地后自动出现——两侧零耦合。

## 10. 分步实施清单 S0–S6（派工前置细化，2026-09-30）

> 体例循 [udp-mesh-dataplane.md](udp-mesh-dataplane.md) §9.1.1：每步给**落点 / 依赖 / 交付 / 测试计划**；一步一 commit、全仓测试保持全绿再进下一步（沿用 P0-4 节奏）。
> 依赖链：**S0 与 S1 互不依赖（可并行）→ S2 依赖 S0+S1 → S3 仅依赖 P0-4（已落地，可与 S0–S2 并行）→ S4 依赖 S2+S3 → S5 依赖 S4 → S6 收尾**（面板查询名以 S4 定稿序列名为准）。

### S0 配置面（seep-config）

- **落点**：`crates/seep-config/src/lib.rs`——`UdpConfig` 增 §1.2 表 5 字段（serde 全 `#[serde(default)]` + 缺省常量）、`UdpConfig::validate()` 增约束（`sweep_interval_secs ≥ 1`、`max_mappings ≥ 1`、`session_lifetime_secs` 存在时 `≥ session_idle_secs`、`downlink_queue_depth ≥ 1`、`max_associates ≥ 1`）、`IngressConfig::{Socks5, Mixed}` 增 `#[serde(default)] udp_enabled: Option<bool>`、`pub(crate) fn resolve_udp_enabled`（§9-4，S2 消费）。
- **依赖**：无。
- **测试计划**（seep-config 现有测试文件追加）：
  1. `udp_config_defaults_backward_compatible`——不含 `udp:` 块 / 含旧 5 字段缺新字段，两份 YAML 均解析成功且新字段等于 §1.2 缺省（验收 #1 前半）；
  2. `udp_config_validate_rejects_illegal`——sweep=0 / max_mappings=0 / lifetime<idle / queue_depth=0 / max_associates=0 五组逐个 `Err`（验收 #7）；
  3. `resolve_udp_enabled_three_states`——None 继承全局 / Some(false) 显式关 / Some(true) 显式开（§9-4 三行钉死）；
  4. `ingress_udp_enabled_serde_roundtrip`——socks5 与 mixed 条目带/不带 `udp_enabled` 序列化往返等价（缺字段 = None）。

### S1 核心计数与上限（seep-core）

- **落点**：`metrics.rs`——`TableMetrics` 增 `bytes_up/bytes_down: AtomicU64`（+读取方法）、`TableSnapshot` 增两字段、新 `UdpIngressSnapshot`（字段名 = `UdpIngressMetrics` 原子量既有名，§9-1 ingress 段九字段）；`table.rs`——369/608 两处顺带累加（§2.5 落地核对）；`associate.rs`——`UdpAssociateService` 增 `max_associates`（构造参数，缺省 256 由调用方 S2 传）、`try_register_associate` 增总量门（现仅同 peer 去重，超 `active.len() ≥ max` 拒）。
- **依赖**：无（S0 无关）。
- **测试计划**（seep-core/tests 追加）：
  1. `table_bytes_aggregate_tracks_mappings`——单会话上下行若干包后表级 `bytes_up/down` == per-mapping 快照求和；再并发写断言单调不减、终值一致（复用既有并发压测脚手架）；
  2. `max_associates_cap_rejects_and_counts`——max=2 下两个不同 peer 注册成功、第 3 个返回 false 且 `associate_rejected` +1；同 peer 重复注册维持既有拒绝语义；
  3. `ingress_snapshot_fields_complete`——驱动各类事件后 `UdpIngressSnapshot` 九字段逐一断言（含 0 值字段存在，§6-2 口径）。

### S2 运行时接线（seep-runtime/runtime_builder）

- **落点**：build() UDP 块——`UdpSessionConfig{..Default::default()}` 改为显式映射（提纯函数 `udp_session_config(&UdpConfig) -> UdpSessionConfig`，S0 五字段全覆盖）；`UdpAssociateService::new` 传 `max_associates`；`build_ingress_endpoints` 增全局开关参数，逐入口 `resolve_udp_enabled(global, desc.udp_enabled)` 决定传 `Some(Arc::clone(udp))` 还是 `None`（服务实例仍全局单例，§1.3）；`Some(true)` 且全局关 → `tracing::warn!(target: "seep::boot", …)` 一次（§2.7）；`Runtime` 增 `get_udp_service()`。
- **依赖**：S0（字段/判定函数）+ S1（`max_associates` 参数）。
- **测试计划**（runtime_builder tests，循 P0-4 S5 build 级四测体例）：
  1. `udp_session_config_mapping`——纯函数对样例 `UdpConfig` 逐字段断言（含 `session_lifetime_secs` None/Some 两态），防「字段加了没接线」；
  2. `per_ingress_override_disabled_entry_rejects_associate`——全局开 + socks5 显式 `udp_enabled: false`：起该入口（127.0.0.1:0）发 CMD 0x03 得 0x07，另一 mixed 入口不受影响可受理（P0-2 测试提供 ASSOCIATE 收发脚手架；§1.3 三态的行为级验证）；
  3. `per_ingress_override_true_enables_when_global_off`——全局关 + mixed 显式 true：该入口可受理 ASSOCIATE（构建期 WARN 不强测，判定与装配为准）；
  4. `udp_disabled_all_ingress_closed`——全局关且无覆盖：全部入口 CMD 0x03 → 0x07（验收 #4 构建断言半边；端口扫描半边归验收阶段）。

### S3 mesh 面观测装配（seep-runtime：mesh_transport + udp_chain）

- **落点**：`mesh_transport.rs`——`pub struct UdpFaceSnapshot`（六字段：`forwarded_up/forwarded_down/malformed/flows_active/unknown_flow/evicted`——后两者从 `UdpFlowCache` 收编，防双计口径不变）、`UdpFace::snapshot()`、`MeshDataPlane::udp_snapshot() -> Option<UdpFaceSnapshot>`；`udp_chain.rs`——`UdpClientMetrics{dropped}`（§2.4 收编裁决）；`runtime_builder.rs`——`Runtime` 增 `mesh_plane: OnceLock<Arc<MeshDataPlane>>`（start() 在 `spawn_udp` 后 `set`，恰好一次、观测只读，不引入 ArcSwap）与 `udp_client_metrics: Option<Arc<UdpClientMetrics>>`（build() 包装 `UdpChainRouter` 前从 bridge 抽出）+ 两个 getter。
- **依赖**：仅 P0-4（已落地），与 S0–S2 并行。
- **测试计划**（mesh_transport/udp_chain tests，复用 T2/T7 脚手架）：
  1. `udp_face_snapshot_after_roundtrip`——T2 式两跳小流量后两侧 `udp_snapshot()` 数值断言（exit：forwarded_up/down=2、flows_active=1、unknown_flow/evicted/malformed=0）；
  2. `udp_client_metrics_shared_across_relays`——同 bridge 两次 `associate`，向其一注入非匹配下行包（dir=Up 回包）→ 共享 `dropped` 跨 relay 累加（收编语义钉住）；
  3. `runtime_mesh_plane_backfilled_after_start`——复用 S5 测试 helper（chain+udp+显式明文）start() 于 127.0.0.1:0 后 `get_mesh_udp_snapshot()` 为 `Some` 且全零；client-only build（无 gate）返回 `None` 同测钉住。

### S4 控制面渲染（apps/seepd/control_plane）

- **落点**：`handle_metrics` 追加 §2 全序列（无标签 gauge 走 `push_gauge`；direction/reason 序列走 `push_metric_header(counter)` + 封闭枚举成员逐条 `push_metric_labeled`，§2.1 落地核对）；新路由 `(GET, "/udp/stats")` → `handle_udp_stats`（§3.1/§9-1 JSON，含 `mesh` null 两态与 `mesh_client` 条件键）。
- **依赖**：S2（getter/数据可达）+ S3（mesh 快照）。
- **测试计划**（seepd tests）：
  1. `metrics_contains_full_udp_family`——udp 关闭的默认 runtime 请求 `/metrics`：§2.2/§2.3/§2.4 序列名逐条命中且值为 0（验收 #2；恒渲染口径）；
  2. `metrics_udp_counters_after_traffic`——socks5 ASSOCIATE + 环回 echo（P0-2 集成先例）后 `seep_udp_relay_packets_total{direction="up"}` ≥ 1、bytes 序列非零；
  3. `udp_stats_endpoint_shape`——`/udp/stats` 反序列化对齐 §9-1 结构；`mesh` 键两态（未启用 null / 启用对象）各一测。

### S5 seepctl（apps/seepctl）

- **落点**：`main.rs`（stats 改造 §3.2 + `udp-probe` 子命令 clap 接线与退出码映射 §9-3）+ 新 `udp_probe.rs`（§3.3 核心逻辑）。
- **依赖**：S4（`/udp/stats` 端点；probe 只依赖 socks5 入站，但统一排在 S4 后收口）。
- **测试计划**（seepctl tests）：
  1. `udp_probe_roundtrip_against_local_stub`——进程内最小 socks5 UDP echo 桩（TCP 协商 + ASSOCIATE 应答 + UDP 回环，真 socket 无特权，P0-2 同法）→ `udp_probe::run()` Ok 且 RTT > 0、源/长度回填正确（验收 #6 的桩级口径）；
  2. `udp_probe_rejected_maps_exit_code_2`——桩回 REP 0x07 → 退出码 2、stderr 含「入口未开 UDP」语义；
  3. `udp_probe_timeout_maps_exit_code_3`——桩吞包不回 → 1ms 级 timeout 触发退出码 3；
  4. `stats_udp_section_render`——给定 §9-1 JSON → §9-2 文本逐行断言（纯函数，零网络）。
  - 真 seepd 全链路（probe → seepd → direct 出站 → 环回 DNS 式目标）留验收阶段手动/脚本执行（验收 #6 全口径），CI 不依赖外网。
- **注记**：`udp-probe` 的 SOCKS5 认证参数（`--user/--pass`）只实现无认证与用户名/密码法（METHOD 0x00/0x02），与入口现有能力对齐，不做扩展协商。

### S6 样例与面板（config/ + docs/grafana/ + 文档回填）

- **落点**：`config/seep.yaml`——`udp:` 注释样例区块（全字段 + 「变更重启生效」注记 §1.6）+ mesh 明文门注释样例（§1.5）；`docs/grafana/seep-dashboard.json`——§5 四行面板（查询名 = S4 定稿序列名）；todo.md 勾选与 PROTOCOLS.md/README 状态回填。
- **依赖**：S4（序列名定稿）；可与 S5 并行。
- **测试计划**：
  1. `grafana_dashboard_json_parses`——seepd tests 读 `docs/grafana/seep-dashboard.json`（`CARGO_MANIFEST_DIR/../../` 相对路径）serde_json 解析 + 断言含 `seep_udp_` 查询串（防手改坏 JSON/漏序列）；
  2. `sample_config_parses_with_udp_block`——`config/seep.yaml` 全文经 `SeepConfig::from_str` 解析成功（样例即文档，坏样例构建期即红）；
  3. docs 内链验证（`npm run build` 死链检查，仓库既有门槛）。

### 验收映射（§6 → 步骤）

| §6 验收项 | 承载步骤 |
|----------|---------|
| #1 示例配置含 UDP 区块 + 旧配置兼容 | S0（测试 1）+ S6（样例落盘） |
| #2 /metrics 全序列恒存在 | S4（测试 1/2） |
| #3 Grafana 面板可见 UDP 序列 | S6（测试 1 + dashboard 入库） |
| #4 udp.enabled=false 无 UDP 监听 | S2（测试 4，构建/行为断言）+ 验收阶段端口扫描 |
| #5 seepctl stats 显示 UDP 段 | S5（测试 4） |
| #6 udp-probe 全链路往返 | S5（测试 1–3 桩级）+ 验收阶段全链路 |
| #7 配置项全过 validate | S0（测试 2） |
