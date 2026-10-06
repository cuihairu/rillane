# P0-2 / P0-3 实现级设计：单跳 UDP 中继路径

> 状态：**已落地（todo P0-2/P0-3 完成，2026-09）**· 本文是 [udp-dataplane.md](udp-dataplane.md) §2/§3 的展开，为两条目的实现口径 · 依赖会话表契约：[udp-session-table.md](udp-session-table.md) · 对应 [todo.md](../../todo.md) P0-2/P0-3 · 上游：[roadmap.md](roadmap.md) S1
> 实施面 = `seep-core/src/udp/associate.rs`（入站）+ `seep-protocols` 出站承载连接器；设计原文保留，偏差以各节落地注记为准。

## 执行摘要

P0-2（SOCKS5 UDP ASSOCIATE 入站）与 P0-3（direct/ss/hy2/wg 出站承载）共享同一条**单跳中继路径**，本文给出实现级设计：入站侧的控制面命令分支、数据报 10 字节头解析、BND 应答语义、ASSOCIATE 生命周期与会话表回收挂钩；出站侧的静态能力表与构建期报错、四个协议各自的承载方式、`UdpRelay` 错误到 `FailureType` 的分类契约。文末为两条目的验收测试映射。

## 1. 端到端包流（单跳视图）

```
上行：client ──[SOCKS5 UDP 头|data]──► relay socket ──解析/校验──► UdpSessionTable（粘滞键命中）
        ──► mapping.binding（direct=Local socket / 协议出站=UdpRelay 句柄）──► 目标
下行：目标 ──► per-mapping forwarder task（表侧 spawn）──► downlink mpsc ──► 入站消费循环
        ──► 封 SOCKS5 UDP 头 ──► client
```

字段变换：入站剥 `[RSV(2) FRAG(1) ATYP(1) ADDR(var) PORT(2)]` 得 `FlowTarget`；下行按同一格式重封（`ATYP` 按目标地址族回填 IPv4/IPv6/域名）。会话表内部（粘滞、映射、回收）见 [udp-session-table.md](udp-session-table.md)，本文不重复。

## 2. P0-2：SOCKS5 UDP ASSOCIATE 入站

### 2.1 控制面命令分支（复用现有框架）

`inbound/socks5.rs` 现有 `negotiate_method`（0x00/0x02）/`perform_auth`/`parse_request`（ATYP 0x01/0x03/0x04）全部复用；`parse_request` 当前 `header[1] != 0x01 → send_error(0x07)` 改为命令分派：

| cmd | 行为 |
|-----|------|
| 0x01 CONNECT | 现状路径不动（`Flow{io}` 流式） |
| 0x03 UDP ASSOCIATE | 新增：绑定中继 socket → 应答 BND → 进入数据面（§2.3/§2.4） |
| 其他（含 0x02 BIND） | `0x07 Command not supported`（现状） |

认证语义：`udp_enabled=false` 时 0x03 回 0x07（与现状一致，总开关见 udp-dataplane.md §5.2）；认证通过与否不影响 ASSOCIATE 可用性，但影响粘滞键 `user` 维度（udp-session-table.md §3.1）。

### 2.2 中继 socket 绑定与 BND 应答

- 中继 socket **与 TCP 监听同端口号**绑 UDP（TCP/UDP 端口空间独立）；
- 应答帧：`BND.ADDR = 0.0.0.0`、`BND.PORT = 中继 socket 实际绑定端口`——与现有 `send_success` 回零不同，UDP **端口必须真实**（客户端凭它发数据报），地址回零由客户端按控制连接对端 IP 处理（Clash/sing-box 惯例）；多宿主兼容问题与 `advertise_addr` 预留 = 上游 R3；
- 客户端期望发往 `BND`，实际数据报源地址记入粘滞键 `client`（五元组基线）。

### 2.3 数据报解析与准入

每包流程（中继 socket 的 recv 循环内）：

1. 解析 SOCKS5 UDP 请求头（≥10 字节；`ATYP` 0x01/0x04 为 4/16 字节地址，0x03 域名变长）；
2. `FRAG != 0` → 丢弃 + `seep_udp_packets_dropped_total{reason="frag"}`（MVP 不做分片重组，上游 O2）；
3. 源校验 `strict_udp_source`（默认开）：数据报源 IP ≠ 控制连接对端 IP → 丢弃 + 计数（防中继被第三方借用，上游 R7 的入站侧）；
4. 组 `UdpSessionKey{client=(src ip, src port), user, process:None}` 查会话表；未命中走首包路径（路由决策 → 建会话/映射，udp-session-table.md §3.3）；
5. `binding.send_to(target, data)`。

**换源端口语义**：客户端换 UDP 源端口 = 新粘滞键 = 新会话，旧会话靠 `session_idle` 回收，不做迁移（udp-session-table.md §3.2 已定）；诊断时可由 `client_info.address` 对照排查。

### 2.4 下行消费循环

入站侧为每个 ASSOCIATE 持有 `downlink_rx`，循环：`DownlinkPacket{target, data}` → 封 `[00 00 00 | ATYP | ADDR | PORT]` → `send_to(client_addr)`。`client_addr` 取控制连接对端地址。通道满（容量 64）时丢下行 + `dropped{reason="no_mapping"}` 区分计数——UDP 无背压，宁丢不阻（背压策略在 §4.3 统一定义）。

### 2.5 ASSOCIATE 生命周期与会话表挂钩

RFC 1928：TCP 控制连接终止，服务器应结束该关联。落地：

- 会话表新增 `force_revoke(key)`：立即执行回收动作清单（udp-session-table.md §4.5），不等空闲扫描；
- 入站侧在控制连接 EOF/错误时调用之；中继 socket 与消费循环随会话回收终止；
- 反向（会话空闲到期）**不关**控制连接：TCP 侧保持，客户端下一个包会重新建会话（省一次 ASSOCIATE 往返）；空挂控制连接的资源代价见 O8。

### 2.6 并发 ASSOCIATE（同键）

同一 `client (ip, port)` 的第二个 ASSOCIATE：MVP **拒绝**（应答 `0x01 general failure`）+ 计数。理由：`downlink` 是单消费 mpsc，双消费需要 fan-out 结构；而同源端口双 ASSOCIATE 属客户端异常使用（正常双游戏 = 两个 UDP 源端口 = 两个键）。定稿讨论列 O9。

### 2.7 验收对齐（todo P0-2）

| 验收原文 | 测试 |
|---------|------|
| 标准客户端经 socks5 入站 + direct 出站完成 DNS UDP 查询往返 | 集成：`dig @8.8.8.8 example.com` over socks5（UDP ASSOCIATE）+ direct 出站，往返断言 |
| `seepctl stats` 可见 UDP 会话 | 会话表指标接入 `/flows` 快照后 `seepctl stats` 呈现（P0-5 联动） |
| （udp-dataplane §2.4 补充）开关关闭回 0x07 | `udp_enabled=false` 下 0x03 → 0x07；CONNECT 无回归 |
| （本稿新增）头解析与准入 | FRAG≠0 丢弃计数；伪造源 IP 丢弃计数；10 字节头截断包不 panic |

## 3. P0-3：出站 UDP 承载

### 3.1 静态能力表与构建期扫描

| EgressConfig 变体 | UDP 能力 | 承载方式 |
|-------------------|---------|---------|
| `Direct` | 是 | 本地 UDP socket（§3.2） |
| `Shadowsocks` | 是 | crate UDP relay（§3.3） |
| `Hysteria2` | 是（以 V1 核查为前提） | QUIC 数据报（§3.4） |
| `WireGuard` | 是 | IP 包封装（§3.5） |
| `Socks5` / `Http` / `Trojan` / `Vless` | 否（S1 范围外，udp-dataplane.md §3.5） | 构建期报错 |
| `Vmess` | 否（TCP 连接器已落地 2026-10-02；UDP 承载未实现，构建期扫描即报错） | 同上 |

- `RuntimeBuilder` 构建期：对 `routing.rules`/`default_node`/组 `members` 可达的全部出站求 UDP 能力闭包；UDP 流量可达但无 UDP 能力的节点 → **启动失败**，错误信息逐个列出节点名与规则来源（todo P0-3 验收"构建期明确报错"）；
- mesh 目标（`mesh.*`）不在本表，P0-4 另行处理（udp-dataplane.md §4）。

### 3.2 direct

`UdpSocket::bind("0.0.0.0:0")` → `connect(target)` → 包成 `UdpBinding::Local`。send 错误含 `ConnectionRefused`（目标端口未开）→ 归类 `FailureType::Timeout`（§3.6），映射保留由空闲回收——游戏服务器常用"不回第一个包"探测，不因 ICMP 立即拆映射。

### 3.3 shadowsocks

- 复用 workspace `shadowsocks 1.21` 的 UDP relay 能力（`relay::udp`），每包独立 `[salt][AEAD(目标地址+数据)]`，无连接语义，天然适配映射模型；
- `method` 合法性校验从"运行时首个包报错"**提前到构建期**（顺带修复 TCP 面同款体验）；
- 上游 R7（开放解析器）落地口径：出站只发 `associate(ctx)` 时锁定的 `ctx.target`，映射层不存在"任意改址"接口——目标白名单由会话表结构保证。

### 3.4 hysteria2（前置 V1 核查）

实施第一工单 = 核查 `hysteria2 0.1.6` 四个检查点：① 是否暴露 UDP/session API；② 数据报与 TCP 会话是否共享连接管理；③ 关闭语义（TCP 侧断是否连坐 UDP）；④ 带宽/拥塞参数入口。结论分支：a) API 可用 → 直接接；b) 缺失 → 基于 quinn 自实现 hy2 UDP 通道（协议口径见 udp-dataplane.md §3.3）；c) 工作量超预算 → P0-3 验收降级（hy2 改 P0-4 后补，**需在 todo 上显式改验收**，不静默缩水）。TCP/UDP 共享 QUIC 连接的生命周期隔离（③）为实施硬要求。

### 3.5 wireguard

- 承载 = 构造 IP 包写入系统 WG 接口（与 TCP 面同轨，WG 本身 L3）：

```
IPv4: [20B IP 头（src=WG address 配置, dst=target, proto=17, 校验和）| 8B UDP 头（sport=映射分配, dport=target.port, 校验和）| data]
```

- `allowed_ips` 预检复用现有校验语义（目标不在网段 → 构建映射时即报错，归类 `FailureType::Route`）；
- MTU 预算：WG 接口 MTU（配置默认 1420）− 外层封装 → 应用载荷上界 ~1400B，超限包丢弃 + 计数（上游 R8，实测填数）；
- 源端口分配：每映射固定伪随机 port（首包定，会话期不变），保证下行分路正确。

### 3.6 UdpRelay 错误分类契约（会话表 ↔ 出站）

| 错误形态 | FailureType | 会话表动作 |
|---------|-------------|-----------|
| 绑定/握手失败（associate 阶段） | `Connection` | 映射不建，`record_failure` + `dropped{reason="no_mapping"}` |
| send/recv IO 错误（传输中） | `Connection` | `record_failure`；连续 ≥3 次触发映射重建（同目标重 associate） |
| 目标不可达/超时（ICMP、ss 无响应） | `Timeout` | `record_failure`，映射保留待空闲回收 |
| 路由不可达（wg allowed_ips 等） | `Route` | 映射关闭 + 决策缓存清除（触发重路由，udp-session-table.md §3.4） |

所有错误经 §2.4 下行通道无感——客户端只观察到丢包，符合 UDP 语义。

### 3.7 验收对齐（todo P0-3）

| 验收原文 | 测试 |
|---------|------|
| QUIC 站点（HTTP/3）分别经 hy2 与 wg 出站可访问 | 集成：`curl --http3` 经两出站各一轮（前置：V1 通过） |
| 不支持的出站类型在构建期明确报错 | 规则指向 trojan/vless 节点 → 启动失败、错误含节点名与规则名 |
| （udp-dataplane §3.6 补充）DNS 查询经 ss 出站往返 | 集成：`dig` over ss UDP |
| （本稿新增）错误分类 | §3.6 表逐行注入故障，断言 `FailureStats` 对应计数与映射行为 |

## 4. 与会话表的接口契约

1. **associate 时机**：首包路由决策产出后、映射创建处（表侧），一次一映射；重连（§3.6 连续错误）复用同一调用；
2. **forwarder task 归属表侧**：出站只交付 `UdpRelay` 字节级句柄；收包循环、下行投递、指标、错误分类全部在表侧统一 spawn/收口——出站实现保持"纯管道"，新增出站零观测代码；
3. **背压策略**：所有下行通道容量 64、满即丢 + 计数；上行无队列（直接透传 send）。全链路（入站 §2.4 / 表 §4 / P0-4 跳间）统一此口径。

## 5. 边界与开放问题

| 编号 | 内容 | 衔接 |
|------|------|------|
| O8 | 空闲回收后控制连接仍挂：客户端视角"ASSOCIATE 仍有效但包被静默重建会话"。MVP 接受；是否到期回 ICMP/显式关闭待定 | 实施期定，无依赖 |
| O9 | 同键并发 ASSOCIATE 拒绝策略（§2.6）是否放宽为 fan-out | 有真实客户端需求再议 |
| V1 | hy2 crate 能力核查 = P0-3 第一工单（§3.4 四检查点） | 决定验收口径是否降级 |
| R3/R7/R8 | BND 地址多宿主 / ss 防滥用（本文 §3.3 已落地结构保证）/ WG MTU | 见 udp-dataplane.md §7 汇总 |

## 6. 实施注记（P0-2 落地裁决，2026-09）

代码：`seep-core/src/udp/associate.rs`（服务与准入）、`seep-protocols/src/inbound/socks5.rs`（命令分派）、`seep-runtime/src/runtime_builder.rs`（接线）、`seep-config`（`udp:` 块）。测试：`seep-core/tests/udp_associate.rs`（11 项）+ `udp_session_table.rs` §3.6 分级 teardown 4 项。

| # | 草案 | 实施 | 裁决理由 |
|---|------|------|---------|
| 1 | §2.4 下行满 `dropped{reason="no_mapping"}` | `DropReason::DownlinkFull`（表侧语义命名） | "映射存在但通道满"与"无映射"是两种事件，混称误导 |
| 2 | SOCKS5 UDP 帧编解码归属未定 | `seep-core::udp::associate`（`parse_udp_header`/`encode_udp_header` 纯函数） | 服务循环每包编解码需与表同侧；protocols→core 依赖方向顺从 |
| 3 | §2.6 并发门键 | 控制连接对端 (ip, port)；数据报源以实测入粘滞键 | ASSOCIATE 时刻数据报源未知；同键判定在门层、会话键在表层，两层各自成立 |
| 4 | §3.6 落地口径 | 发送侧分级 teardown：Route→拆映射+清决策缓存；Timeout→保留映射（计数归零）；Connection→连续 ≥3 拆（成功归零）；recv 侧错误（forwarder）直接退映射 | recv 错误即 relay 已死无恢复路径；send 侧按 §3.6 表逐行实现并有测试钉住 |
| 5 | 回收任务启动时机未定 | 首个 ASSOCIATE 的 `Once` 拉起 `spawn_reclaimer` | build 阶段无 tokio 上下文；会话不可能先于 ASSOCIATE 存在 |
| 6 | P0-2 路由面 | 基础 `RoutingEngine` 实现 `FlowRouter`；mesh-chain 感知的 UDP 路由归 P0-4 | 单跳范围（本文 §1）；RuntimeFlowRouter 包装依赖 mesh 组件，P0-4 一起接 |
| 7 | `EgressUdpConnector::associate` 返回类型 | `Arc<dyn UdpRelay>`（非 Box，与 api 文档 §9 #3 同口径） | forwarder 与发送路径共享所有权 |
| 8 | mixed 入口未提 | `MixedIngress` 同享 ASSOCIATE（同一服务实例透传） | socks5 分支复用同一条处理路径，无额外成本 |
| 9 | `perform_auth` 无返回 | 返回认证用户名 → 粘滞键 `user` 维度 | udp-session-table.md §3.1 的 user 维度接线点 |

**验收状态（§2.7）**：DNS 式 UDP 往返（真 socket、strict 源校验开、direct 出站、下行封帧）已由 `dns_style_roundtrip_via_associate_and_direct` 钉住；FRAG≠0 / 截断头 / 伪造源（127.0.0.2）/ 并发 ASSOCIATE 拒绝各有独立测试。"标准 CLI 客户端（curl/dig）+ `seepctl stats` 可见"的联调归 P0-5（观测接线后）。

## 7. 实施注记（P0-3 落地裁决，2026-09）

代码：`seep-core/src/udp/relay.rs`（RoutingUdpConnector + trait 签名）、`seep-protocols/src/outbound/{shadowsocks,wireguard}.rs`（UDP 面）、`seep-runtime/src/runtime_builder.rs`（§3.1 能力扫描 + 接线）。测试：`seep-core/tests/udp_egress_selection.rs`（3 项）+ `seep-protocols/tests/udp_egress.rs`（7 项）+ `seep-runtime` 能力扫描 4 项。

| # | 草案 | 实施 | 裁决理由 |
|---|------|------|---------|
| 10 | §3.4 hy2 V1 核查 | **分支 (c)：推迟 P0-4**。核查 hysteria2 0.1.6：公开 API 仅 `HysteriaClient::connect` + `tcp_connect`（open_bi）；`quic_connection` 为 `pub(crate)`，无任何 UDP/QUIC 数据报出口 | 不静默缩水：todo P0-3 验收已显式改写，"QUIC 站点经 hy2 出站可达"移入 P0-4（与 mesh UDP 载荷同批，届时换 crate 版本或直用 quinn）——**后记（2026-09-30）**：P0-4 完成时**维持改判**，hy2 UDP 终态 = V2（quinn 载具，todo P0-4 §0.1-③） |
| 11 | §3.4 `associate(ctx)` 签名 | 扩为 `associate(ctx, decision: &RouteDecision)`；`RoutingUdpConnector` 按决策 `final_node()` 分发到节点连接器 | 载体选择必须用会话的**粘滞决策**（resolve 时已缓存），重新路由会破坏同会话同出口；未注册节点报错点名（能力表扫描兜底） |
| 12 | §3.5 wg 承载机制 | 系统接口（wg-quick 风格）下 UDP 走**内核路由**：本地 UDP socket `connect` 目标，内核导入 wg 接口；不做手工 IP 构造 | 与本仓 TCP 面 wireguard 连接器同一架构；userspace 手工封装是另一条代码路径（P1 TUN 时再评估） |
| 13 | §3.5 wg 预检 | `allowed_ips` 构建期解析 CIDR（无效即启动失败）；associate 时先解析目标（域名→IP），不在任何网段 → Route 类错误"…不在 wireguard allowed_ips 网段内"；网段为空不预检（交内核路由） | 错误信息携带 `allowed_ips` 关键词供 classify_failure 归 Route（拆映射+清决策，§3.6） |
| 14 | §3.5 wg MTU | 载荷上限 = `mtu-80`（未配置保守 1400）；超限在 connector 侧丢弃，错误"wireguard MTU 超限…"归类 **Timeout**（映射保留待空闲回收） | R8 丢弃+计数口径：send_failed 计数在表侧累加；Timeout 行为最接近"包级瞬态损失不拆映射" |
| 15 | §3.3 ss | 加密方法校验提前到 `ShadowsocksConnector::new`（TCP/UDP 共用同一 `ServerConfig`，方法无效构建期报错）；客户端 socket 用 `ProxySocket::connect`（`bind` 是服务端入站监听）；目标在关联时固定（R7） | ss UDP 无连接语义、目标随包携带：固定目标即映射语义；shadowsocks 1.24.0 API 核实 |
| 16 | §3.1 扫描范围 | 可达集 = default_node + 规则目标 + 组成员闭包（Weighted 节点/组一并展开）；**非本配置出站节点的目标（如 `mesh.exit1`）跳过**（路由器自行解析）；错误逐个列出节点名/类型/来源（`default_node` / `rule:{name}` / `group:{name}`） | mesh 节点的 UDP 能力属 P0-4 mesh data-plane，不归本扫描误报 |

**测试口径（§3.7）**："QUIC 站点经 direct/wg/ss 出站可达"由发送路径真 socket 测试 + §3.6 分类全链路测试钉住（ss 完整解密往返需 `shadowsocks-service` 服务端，仓库未依赖，归 P0-5 联调）；"不支持的出站类型构建期明确报错"由 `scan_udp_capability` 系列测试钉住（点名节点、类型、规则来源）。hy2 验收按 #10 移 P0-4（P0-4 已于 2026-09 完成并**维持改判**，hy2 UDP 终态 = V2——todo P0-4 §0.1-③）。
