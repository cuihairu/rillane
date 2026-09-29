# P0-5 UDP 观测与配置 — 实现级设计

> 上游设计：[udp-dataplane.md](udp-dataplane.md) §5（P0-5 概念稿：配置示意/指标草案/R11 基数风险/O4 未决）。
> 本文是落地定稿：**配置项清单、`/metrics` 命名与语义、seepctl 渲染、与 P0-4 数据面的衔接点**。
> 复用基线：P0-1 会话表指标（`TableMetrics`/`TableSnapshot`）· P0-2 ASSOCIATE 指标（`UdpIngressMetrics`）· P0-3 能力表 · P0-4 mesh UDP 面（`udp-mesh-dataplane.md`）。

## 0. 范围

- `seep-config` 的 `udp:` 区块补齐（P0-2 只暴露了 `UdpSessionConfig` 7 字段中的 3 个）；
- `/metrics` 增 `seep_udp_*` 全集（会话/关联/字节/丢弃/过期 + P0-4 mesh 面）；
- `seepctl stats` 增 UDP 段 + 新增 `seepctl udp-probe` 联调工具（收口 P0-2 遗留的"标准客户端联调"）；
- Grafana dashboard 追加 UDP 面板行；
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

### 1.5 mesh UDP 面配置（P0-4 衔接）

| 字段/来源 | 缺省 | 语义 |
|----------|------|------|
| env `SEEP_MESH_UDP_ALLOW_PLAINTEXT` | 未设 | P0-4 明文门（镜像 TCP 面 `SEEP_MESH_ALLOW_PLAINTEXT`）；chain+udp 未配加密时唯一放行途径 |
| `MeshConfig.udp_allow_plaintext_data_plane`（新增，serde default false） | `false` | env 的持久化等价物；两者取或 |

### 1.6 热更新语义与校验

- **UDP 配置变更重启生效**：订阅热更新管线不触碰运行期 `UdpSessionTable`/`UdpAssociateService` 参数（粘滞决策与会话状态不可热迁移）；存量会话按旧超时自然回收。文档与 `seepctl` 帮助文本明示。
- `UdpConfig::validate()` 新增字段约束随实现补齐（表内列），非法值构建期报错。

## 2. /metrics 指标命名与语义

### 2.1 渲染路径与约定

- 导出点：`apps/seepd/src/control_plane.rs::handle_metrics`（与 `seep_chain_*`/`seep_mesh_link_bytes_total` 同一 `push_counter`/`push_gauge` 渲染函数）；
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

### 2.5 字节聚合的实现裁决

现状字节计数只在 per-mapping（`MappingShared.bytes_up/bytes_down`）。`/metrics` 抓取若扫描全表聚合为 O(活跃会话)，scrape 开销随负载波动。**裁决**：`TableMetrics` 增全局 `bytes_up`/`bytes_down` AtomicU64，在既有计数点（`count_up`/`count_down` 调用处）顺带累加——渲染零扫描；per-mapping 数值保留给 `SessionSnapshot`（seepctl/stats 详单用）。

### 2.6 /flows 与 /chains/stats 的裁决（关闭上游 O4）

- **`/flows` 不加 proto 维度**：UDP 会话不经过 `FlowOutputRouter`（P0-2 起 UDP 面直接进会话表，无 FlowStatItem）；硬拼两套统计模型只会产生语义含混的双口径。UDP 观测口径 = 本文 `seep_udp_*` + `seepctl stats` UDP 段（§3）。
- **`/chains/stats` 不为 UDP 分列**（关闭 O4）：链路维度的 UDP 流量已经由 P0-4 `record_link_bytes` 进入 mesh per-link 序列（`seep_mesh_link_bytes_total`，现成），重复分列无增量信息。

## 3. seepctl：stats UDP 段 + udp-probe 联调工具

### 3.1 控制面快照端点 `/udp/stats`（新增）

control_plane 暴露 JSON：`{ table: TableSnapshot, ingress: UdpIngressMetricsSnapshot, mesh: Option<UdpFaceMetricsSnapshot> }`（快照结构均为既有 `get()`/`get_gauge()` 拼装，无新状态）。

### 3.2 `seepctl stats` 渲染

现 `stats` 打 `/stats`（FlowStatItem 表）——追加 UDP 段：sessions/mappings active·total、dropped×6、expired×3、bytes/packets up·down、associates active·rejected、mesh 段（P0-4 启用时）。

### 3.3 `seepctl udp-probe`（收口 P0-2 "标准 CLI 联调"遗留）

curl/dig 均不支持 SOCKS5 UDP ASSOCIATE（curl 走 TCP、dig 无代理面），proxychains 依赖系统栈不可控。**裁决**：内置最小 RFC 1928 ASSOCIATE 客户端：

```
seepctl udp-probe --socks5 127.0.0.1:1080 --host example.com --port 53 \
                  --payload-hex <DNS 查询hex> [--timeout 3s] [--user u --pass p]
```

流程：TCP ASSOCIATE → 收 BND → 按 §7 头封装目标发查询 → 等回包（解头打印源与载荷长度）→ EOF 撤销。退出码 0=往返成功。作为验收工具直接可执行（不引入新依赖，seepctl 已有 tokio）。

## 4. 与 P0-4 数据面的衔接点（汇总）

| 衔接点 | P0-5 侧 | P0-4 侧（udp-mesh-dataplane.md） |
|--------|---------|--------------------------------|
| 指标 | §2.4 mesh 序列渲染 | `UdpFaceMetrics` 原子量（malformed/unknown_flow/evicted/forwarded/flows_active） |
| 配置·明文门 | §1.5 MeshConfig 字段 + env | `MeshUdpGate::ensure_usable` 消费 |
| 配置·超时同源 | `UdpConfig.mapping_idle_secs` 单一事实来源 | 跳缓存 TTL = mapping_idle（P0-4 §3） |
| 快照 | `/udp/stats` 的 `mesh` 段 | `UdpFace::snapshot()` |
| 链路字节 | 不另设序列（§2.6） | `record_link_bytes` → 既有 `seep_mesh_link_bytes_total` |
| 验收分层 | 渲染/端点测试（P0-5） | 转发行为测试（P0-4 §10）互不覆盖 |

## 5. Grafana 面板（docs/grafana/seep-dashboard.json 追加）

行 1「UDP 会话」：`seep_udp_sessions_active`、`seep_udp_associates_active`、`seep_udp_mappings_active`；
行 2「UDP 流量」：`rate(seep_udp_relay_bytes_total[1m])` by direction、`rate(seep_udp_relay_packets_total[1m])`；
行 3「UDP 质量」：`rate(seep_udp_dropped_total[1m])` by reason、`rate(seep_udp_expired_total[1m])` by reason、`seep_udp_reroutes_total` 增量；
行 4「mesh UDP」（P0-4 启用时）：`seep_udp_mesh_flows_active`、`rate(seep_udp_mesh_unknown_flow_total[1m])`、`rate(seep_udp_mesh_forwarded_total[1m])`。

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
| `crates/seep-config` | `UdpConfig` 补 5 字段 + validate；`IngressConfig::{Socks5,Mixed}` 增 `udp_enabled: Option<bool>`；`MeshConfig` 增 `udp_allow_plaintext_data_plane` |
| `crates/seep-core/src/udp/metrics.rs` | `TableMetrics` 增 `bytes_up/bytes_down`；各 Snapshot 增字段 |
| `crates/seep-core/src/udp/{inner,table}.rs` | `count_up/count_down` 处顺带累加表级字节 |
| `crates/seep-core/src/udp/associate.rs` | `max_associates` 上限；metrics snapshot 结构 |
| `crates/seep-runtime/src/runtime_builder.rs` | per-ingress udp_enabled 判定；新配置字段映射 |
| `apps/seepd/src/control_plane.rs` | `/metrics` UDP 序列渲染；`/udp/stats` 端点 |
| `apps/seepd/src/control_plane.rs`（P1-2 届时） | `seep_tun_*` 序列渲染（定义见 [tun-dataplane.md](tun-dataplane.md) §2.8；本条目不含，见 §9-5） |
| `apps/seepctl/src/main.rs` | stats UDP 段；`udp-probe` 子命令 |
| `docs/grafana/seep-dashboard.json` | §5 四行面板 |
| 示例配置 | udp: 区块样例 |

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
  }
}
```

（`mesh` 段仅 P0-4 面启用时出现；数字为示意。）

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

tun-dataplane.md §2.8 的 `seep_tun_*` 家族渲染走本文同一 `push_counter`/`push_gauge` 管线（§2.1），**不新开端点/机制**；§7 清单已增 P1-2 衔接行。P0-5 实施时不渲染该家族（序列未定义时跳过），P1-2 T5 落地后自动出现——两侧零耦合。
