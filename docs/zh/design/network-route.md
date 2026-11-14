# P1-3 network 配置区块 + rillanectl route apply/clear — 实现级设计

> 上游：[roadmap.md](roadmap.md) S2 · [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §2（B1–B4）与 §5.4（通道裁决）· [tun-dataplane.md](tun-dataplane.md) §1.3（AppliedStep/回滚复用）· §2.6（属主裁决延续）· §2.7（auto-bypass）。
> 本文是落地定稿：**配置 schema、runtime 接线、控制面端点、CLI、幂等/回滚/还原语义、错误路径、测试策略、分步清单**。落地后偏差回填 §9。
> 复用基线：`LinuxRouteManager`（P1-1 T2 产物，**硬依赖**——apply/clear 即其 `AppliedStep` 回滚机制的 CLI 化）· control_plane `(Method, path)` match 分派（`/chains/dry-run` 先例）· clap 嵌套子命令（`Chain{command}` 先例）· route.rs `parse_cidr`/`ipv4_netmask` 助手。

## 0. 范围

| 在本条目内 | 归 V2 / 其他条目 |
|-----------|-----------------|
| `RillaneConfig.network` 区块 schema（rillane-config 镜像类型）+ 转换到 platform `NetworkConfig` | 全局接管（默认路由 + `ip rule` + fwmark + `SO_MARK` 出站标记） |
| rillaned 接线：`enable_network_virtualization` 从配置派生 + `NetworkManager` 让路裁决（§2.2） | transparent/redir（nftables/iptables）、tap/hybrid 模式实现 |
| 控制面三端点（apply/clear/status）+ `rillanectl route` 三动作（含 `--dry-run`） | filtering/dns 子块（P2-8；schema 层就不暴露，见 E2） |
| 幂等/回滚/还原语义（§5） | 进程过滤（= P1-2 `MatchCondition::Process`，走 routing 规则，**不进 network 块**） |
| 用户 bypass 显式列表不暴露（include 负向即 bypass，§1.4 裁决） | 配置热更新（重启生效，对齐 P0-5 §1.6 裁决） |

**实施排序**：R0（schema）无依赖可先行；R1 起硬依赖 P1-1 的 T1（设备）+ T2（LinuxRouteManager）已落地——无设备则路由无可挂靠的 `dev`。

## 1. 配置 schema（rillane-config）

### 1.1 区块形状

```yaml
network:
  mode: tun                    # tun = MVP；transparent/tap/hybrid 构建期报"未实现"（E1）
  tun:
    name: rillane0                # 可选；缺省 None → 内核分配 tun%d（TUNGETIFF 读回）
    mtu: 1400                  # 缺省 1500；≥68（复用 TunConfig::validate 口径）
    ipv4: "10.255.0.1/24"      # 缺省同左；tun 自身网段进 auto-bypass（tun-dataplane §2.7）
    ipv6: "fd00:db8::1/64"     # 可选
    dns_servers: ["1.1.1.1"]   # 仅记录（消费归 P2-8，TunConfig 原样承接）
  routing:
    include:                   # main 表显式路由纳入集（include 语义，tun-dataplane §1.3）
      - "203.0.113.0/24"
      - "2001:db8::/32"
      - "198.51.100.7/32"      # /32 即主机路由，无需单独 Host 表达
```

### 1.2 镜像类型与转换（裁决：镜像而非加依赖）

rillane-config 当前零依赖 rillane-platform（deps 仅 anyhow/serde 系），保持其轻：**rillane-config 定义镜像 serde 类型，rillane-runtime 增 `to_platform()` 转换**（与 `UdpConfig` → `UdpSessionConfig` 同模式——rillane-config 亦不依赖 rillane-core）。

| config 镜像类型（rillane-config） | platform 转换产物（rillane-runtime） |
|-------------------------------|----------------------------------|
| `NetworkBlockConfig { mode, tun: Option<TunBlockConfig>, routing: Option<RoutingBlockConfig> }` | `NetworkConfig { mode, tun, routing, filtering: None, dns: None }` |
| `NetworkBlockMode::{Tun, Transparent, Tap, Hybrid}`（serde 名对齐枚举） | `NetworkMode` 同名变体 |
| `TunBlockConfig { name, mtu, ipv4: Option<String>, ipv6: Option<String>, dns_servers }` | `TunConfig`：`ipv4` 经 `parse_cidr` 拆 `ipv4_addr` + `ipv4_netmask`；`ipv6` 拆 `ipv6_addr` + `ipv6_prefix_len`；`enable_routing = routing.is_some()`；`enable_dns = false`；两个 gateway 字段 None |
| `RoutingBlockConfig { include: Vec<String> }` | `RoutingConfig { mode: Ip, default_gateway: None, dns_servers: 空或承接 tun 块, rules: include 逐条 → RouteRule{name: "include[i]", priority: 100+i, destination: Ipv4Network/Ipv6Network（按解析）, gateway: None, interface: None, route_type: Unicast, metric: Some(0), enabled: true}, bypass_rules: default_bypass_rules(), enabled: true }` |

（`RoutingMode`/`RouteType`/优先级/策略维度不在 config 暴露——MVP 语义唯一，转换处固定；见 §9-6。）

### 1.3 命名裁决（B4 收口）

config 字面量随 platform 枚举用 **`transparent`**，弃计划文案的 "redir"（语义同一）；todo/roadmap 措辞随本文回填。

### 1.4 校验（构建期，`NetworkBlockConfig::validate`）

1. `mode != Tun` → Err（E1，附"V2/后续条目"指引）；
2. `mtu < 68` → Err；`ipv4`/`ipv6`/`include` 每条过 `parse_cidr`，失败 → Err 带原串（E3）；
3. include 条目命中 auto-bypass 集（egress/mesh/control/tun 网段，构建期组装同 tun-dataplane §2.7）→ **剔除 + warning**（不 Err——防环优先于严格，E5）；
4. `routing` 缺省 = 只有设备无路由（合法：纯抓包/测试场景）。

### 1.5 兼容与静默忽略（B2 定向收口）

- 存量配置无 `network:` → `Option` 缺省 None，行为零差异（serde 往返测试钉住）；
- **`NetworkBlockConfig` 加 `#[serde(deny_unknown_fields)]`**——新块无存量兼容负担，拼错子字段立刻报错；全局 `RillaneConfig` 维持宽松（存量配置可能携带额外键，全局收紧是破坏性变更，不做；B2 的"显式告警"以新块严格化部分兑现，全局口径记 §10 未决）。

## 2. runtime 接线

### 2.1 rillaned 派生开关

`apps/rillaned/src/main.rs` 不再只硬编码 mesh/chain：`enable_network_virtualization = cfg.network.is_some()`，`network_config = cfg.network.map(to_platform)`。mesh/chain 两个硬编码 true **不动**（既有行为，非本条目范围，记 §9-8）。

### 2.2 `NetworkManager` 让路（属主冲突裁决，修正 build() ④）

现状：`runtime_builder.rs:165-175` 在 `enable_network_virtualization && network_config` 时构造 `NetworkManager`，其 `initialize()` 必然失败（四工厂恒 Err）——audit §1.2"接线存在但任何配置下都不可用"。P1-3 后 rillaned 会真的设置该开关，此路径将被踩到。**裁决**：

- 构造条件追加 `&& network_config.mode != Tun`——`mode == Tun` 时数据面属主是 `TunIngress`（tun-dataplane §2.6，延续不收编）；`NetworkManager` 保留为 transparent/tap/hybrid 的未来容器，P1 内任何配置走到它即得到工厂的明确 Err（不再静默）；
- `mode == Tun` 且配置携带 filtering/dns 意图——schema 层已被 deny 拦截（§1.5），双保险。

### 2.3 `LinuxRouteManager` 共享句柄

- build() TUN 块构造 `Arc<LinuxRouteManager>`：一份 clone 进 `TunIngress`（启动 apply + 退出 teardown 属主职责），一份进控制面状态（CLI apply/clear/status 消费）；
- **串行化**：apply/clear/status 与启动/teardown 经 manager 内部既有 `Mutex<Vec<AppliedStep>>` 扩为**操作级互斥**（整个 apply 或 clear 持锁执行，步骤短——`ip` 子进程毫秒级）；
- `AppliedStep`（tun-dataplane §1.3）即 status/clear 的数据源：`{argv: Vec<String>, at: SystemTime}`，clear = 逆序撤销全部已记录步骤（**"完全还原"＝还原 rillane 所加的步骤，非清空系统路由表**，§9-7）；
- **RouteControl in-process 契约（2026-09-30 六要素审计补全）**：`LinuxRouteManager` 暴露以下方法供控制面（§3）直接消费（`Arc<LinuxRouteManager>` 自身即契约，**不新起 trait**——单一实现无抽象收益）：

  ```rust
  async fn apply_desired(&self, cfg: &RoutingConfig, dry_run: bool) -> Result<ApplyOutcome>;
  async fn clear(&self) -> Result<Vec<AppliedStep>>;
  fn status(&self) -> RouteStatus;   // 同步读，不持写锁
  // ApplyOutcome { planned, executed, rolled_back: Vec<AppliedStep> }
  // RouteStatus  { device, mtu, up, applied: Vec<AppliedStep> }
  ```

  三方法均经 §2.3 操作级互斥串行；`dry_run=true` 只跑 planner（构造 argv）不执行 executor、不改 `applied`——planner/executor 分离已有 §7.1 断言支撑。

## 3. 控制面端点（control_plane.rs，match 臂风格对齐 `/chains/dry-run`）

| 端点 | 请求 | 成功响应 | 失败响应 |
|------|------|---------|---------|
| `POST /network/route/apply` | `{"dry_run": false}` | `{"planned": [step], "executed": [step]}`（dry_run=true 时 executed 空） | `{"error": "...", "rolled_back": [step]}`（E7：中途失败已逆序回滚） |
| `POST /network/route/clear` | – | `{"undone": [step]}` | 同上 |
| `GET /network/route/status` | – | `{"mode":"tun","device":"rillane0","mtu":1400,"up":true,"applied":[step]}` | – |

`step = {"argv": ["ip","route","replace","203.0.113.0/24","dev","rillane0","metric","0"], "at": 1760000000}`。鉴权继承控制面现状（本机 HTTP，无新增面）。

## 4. `rillanectl route`（嵌套子命令，对齐 `Chain{command}` 形状）

```
rillanectl route apply   [--endpoint URL] [--dry-run]
rillanectl route clear   [--endpoint URL]
rillanectl route status  [--endpoint URL]
```

- `apply`：令 rillaned 按当前配置**重放期望路由集**（幂等，§5）；`--dry-run` 打印 planned argv 不执行；
- `clear`：逆序撤销全部 AppliedStep；
- `status`：设备态 + 已应用步骤表；
- 输出：逐行 argv 表（dry-run 前缀 `plan:`，已执行 `ok:`，回滚 `undo:`）。

## 5. 幂等 / 回滚 / 还原语义（状态机）

- **apply 幂等**：所有步骤 `ip addr replace`/`ip route replace` 天然幂等；重复 apply 产生的 AppliedStep 内容相同——**去重记录**（同 argv 已在册则不重复入账，status 稳定）；测试 = 连续两次 apply 后 `ip route show` 中 include 前缀唯一且属性一致；
- **fwmark escape 步骤（2026-10-05 出站 fwmark 批半边②落地）**：`network.egress_fwmark` ≠ 0 时 planner 在 addr/route 步骤之前追加两步——`FwmarkRule`（`ip rule add fwmark <mark> table 100`；iproute2 无 rule replace，重复 add 报 File exists **视为已生效**——EEXIST 容忍即幂等，不触发 E7 回滚，其余步骤不容忍）+ `EscapeRoute`（`ip route replace default <via_dev> table 100`；via_dev 取 probe main 表首条默认路由（`ip route show default table main` 首行 `default ` 后部分），无默认路由 → 跳过整个逃逸面不报错）；两步同入 AppliedStep 账目，E7 逆序回滚与 clear 还原均覆盖（undo = `ip rule del` / `ip route del default table 100`）；缺省 mark=0 或无默认路由时零新增步骤，与既有行为零差异；dry-run 的 planned 同样可见这两步。escape 表号固定 100（用户自定义段，避开 255/254/253 系统保留）；
- **失败回滚**：apply 中某步非零退出 → 逆序撤销本批已执行步骤 → Err 响应携带 `rolled_back`（tun-dataplane E7 同机制，本条目把它暴露到 CLI 可见）；
- **clear 还原**：逆序撤销全部在册步骤 → 清空 AppliedStep；无步骤时 Ok 空表（E8）；clear 后 TunIngress **继续运行**（数据面空转，包不再入 tun）——语义即用户所求，`status` 可见 `applied: []` + 设备 up；
- **并发**：apply/clear 互斥串行（§2.3）；apply 后紧接 clear = 净还原；
- **启动 apply ≡ CLI apply（2026-09-30 六要素审计补全）**：rillaned 启动时 `TunIngress::run` 对 `apply_desired(cfg, false)` 的调用与 CLI `route apply` 走**同一方法**（幂等重放），差异仅在调用方与是否 dry_run——不存在两条路由写路径；
- **配置文件改动需重启**：`route apply` 重放的是 rillaned **内存中的** `network` 配置（启动时载入，§9-10 热更新不支持）——编辑 YAML 后不重启 rillaned 直接 `route apply` **不会**反映文件改动；`route apply` 的定位是运行期重放/对账/故障恢复，不是配置热加载。

## 6. 错误路径

| # | 错误点 | 条件 | 语义与恢复 |
|---|--------|------|-----------|
| E1 | mode 非 tun | transparent/tap/hybrid | 构建期 Err："未实现（V2/后续条目）" |
| E2 | network 子块未知字段 | deny_unknown_fields | 构建期 Err 带字段名（§1.5 定向收口） |
| E3 | CIDR/mtu 非法 | parse_cidr 失败 / mtu<68 | 构建期 Err 带原串 |
| E4 | routing 缺省 | – | 合法（只建设备不设路由） |
| E5 | include 命中 auto-bypass | 防环 | 剔除 + warning（不 Err） |
| E6 | CLI 连不上 / 无 network 块 | rillaned 未启或未配置 | CLI Err 明示两分支原因 |
| E7 | apply 中途失败 | `ip` 非零退出 | 逆序回滚本批 + Err 携 rolled_back |
| E8 | clear 无步骤 | – | Ok 空表（幂等） |
| E9 | apply/clear 并发 | – | 互斥排队（后到者在前者完成后执行） |
| E10 | 设备不在 | TunIngress 未运行/已退 | Err："TUN 未启用（检查 network 配置与日志）" |

## 7. 测试策略

### 7.1 单测（无特权）

- schema：无 `network:` 旧配置解析 ✓；含块 roundtrip ✓；未知子字段 deny 拒绝 ✓；mode 三非法值 ✓；CIDR/mtu 非法 ✓；
- 转换：`ipv4: "10.255.0.1/24"` → `ipv4_addr=10.255.0.1, ipv4_netmask=255.255.255.0`；include → RouteRule 全字段断言（priority 递增/metric 0/Unicast）；auto-bypass 命中剔除 + warning；
- 回滚（mock executor）：注入第 k 步非零退出 → 断言前 k−1 步收到逆序 undo argv、AppliedStep 清空；
- REST handler：对 mock 路由控制件断言三端点请求/响应形状（含 dry_run 与 E7 形状）；
- CLI：参数 → 请求组装断言（不真发）。

### 7.2 Linux 集成（skip 守卫复用 tun-dataplane §4.2：无 `/dev/net/tun` 或无 CAP_NET_ADMIN → skip）

- apply 幂等：两次 apply → `ip route show` include 前缀唯一、`dev <tun>` 与 metric 断言；
- clear 还原：apply 后 clear → 抓取 apply 前/后 `ip route show` diff 为空（仅 rillane 所加行消失）；
- dry-run：`--dry-run` → planned 打印且 `ip route show` 零变化；
- status：AppliedStep 与实际路由对账。

## 8. 分步实施清单（R0–R4）

提交节奏循 P0-4 §9.1.1 / tun-dataplane §5 铁律：每步 `cargo build` + `cargo test` 全绿 → 单条 commit（引用本文 §节）→ `git fetch origin main` + rebase → push → 下一步；禁 tag/release/force push。

| 步 | 内容与落点 | 依赖 | 验收 |
|----|-----------|------|------|
| R0 | rillane-config：`NetworkBlockConfig`/`TunBlockConfig`/`RoutingBlockConfig` + deny + validate；rillane-runtime：`to_platform()` 转换 | — | 7.1 schema/转换全绿；旧配置零差异 |
| R1 | build() ④ 让路条件（mode != Tun）+ rillaned 派生 `enable_network_virtualization` + `Arc<LinuxRouteManager>` 双句柄 + 操作级互斥 | P1-1 T1+T2 | tun 模式 build 成功且 NetworkManager 不构造；非 tun 模式得到明确 Err |
| R2 | 控制面三端点（apply/clear/status，dry_run 透传） | R1 | 7.1 REST handler 测试 |
| R3 | `rillanectl route` 三动作 + `--dry-run` + 输出格式 | R2 | 7.1 CLI 组装测试 |
| R4 | 7.2 集成测试 + 文档回填（networking.md §2、todo/roadmap 勾选、验收全表核对） | R1–R3 | 7.2 全绿；P1-3 验收逐条核对 |

## 9. 偏差与假设（信息缺失处的自行假设均已注明）

| # | 类型 | 内容 |
|---|------|------|
| 1 | 裁决 | rillane-config 镜像类型 + runtime 转换，不给 rillane-config 加 rillane-platform 依赖（保持 config crate 轻；`UdpConfig` 同模式先例） |
| 2 | 裁决 | mode 字面量 `transparent`（随枚举），弃 "redir"（B4） |
| 3 | 裁决 | MVP 不暴露 `routing.bypass` 用户列表——include 负向即天然 bypass + `default_bypass_rules()` 兜底；显式列表随 V2 全局接管进 schema |
| 4 | 裁决 | `NetworkBlockConfig` deny_unknown_fields（新块无兼容负担）；全局 RillaneConfig 不收紧（存量兼容） |
| 5 | 假设 | REST JSON 形状对齐控制面既有风格（无鉴权本机 HTTP）；`--dry-run` 为 CLI/端点共用参数 |
| 6 | 裁决 | RoutingMode/priority/metric 等策略维度不在 config 暴露（MVP 语义唯一，转换处固定 `Ip`/`100+i`/`Some(0)`） |
| 7 | 澄清 | "clear 完全还原" = 撤销 rillane 所加 AppliedStep，非清空系统路由表 |
| 8 | 范围 | rillaned 的 `enable_mesh`/`enable_chain` 硬编码 true 不动（既有行为，另行条目） |
| 9 | 修正 | todo 验收"apply 后 `ip rule`/路由表符合预期" → MVP 不触碰 ip rule（main 表显式路由口径，tun-dataplane §1.3）；**2026-10-05 fwmark 批半边②修订**：配置 `network.egress_fwmark` 后 apply 期即在表 100 建 `ip rule fwmark` 逃逸规则 + escape 表默认路由（§5 逃逸面，非全局接管——默认路由改写仍归 V2） |
| 10 | 假设 | include 仅收网络前缀 CIDR（/32 表达主机路由）；`RouteDestination::Default`/`Host` 变体不进 schema（V2 全局接管用 Default） |
| 11 | 偏差 | §2.3 `apply_desired(&cfg, dry_run)` 签名落地为 `apply_desired(dry_run)`——manager 构造期已持 `RoutingConfig`（`with_tun_config` 同期注入），cfg 参数无第二来源；返回 `Result<ApplyOutcome, ApplyFailure>` 类型化失败（E7 的 `rolled_back` 结构化负载 anyhow 装不下，端点直接消费） |
| 12 | 偏差 | §2.3「build() 构造 `Arc<LinuxRouteManager>` 双句柄」落地为 `TunIngress::route_manager()` 访问器——TunIngress 属主化设备+路由（tun-dataplane §2.6 延续），控制面经访问器取同一 `Arc<TokioMutex<LinuxRouteManager>>`，无双实例风险；操作级互斥由该 TokioMutex（端点间/与 run() 启动-teardown 串行）+ manager 内部 `Mutex<Vec<AppliedRecord>>`（入账原子）双层承担 |
| 13 | 偏差 | §3 status 端点「失败 –」落地为 503 文本（TunIngress 未装配时，`/nodes` 先例口径）；TunIngress 在场但设备未建（未 start/已退）→ apply 500 `{"error": E10 口径}`、status 仍 200（device null/up false）——两种「TUN 不可用」以装配态分层 |
| 14 | 偏差 | step.at 口径：status 的 applied 携**入账时刻**（`AppliedRecord.at`），apply/clear 响应的 step 携**响应生成时刻**（ executed/undone 无账目语义，求可读不谎称入账时间）；rolled_back/executed/undone 步骤渲染 `undo_argv`（撤销事实——E7 逆序回滚与 clear 还原展示的是将执行的撤销命令） |
| 15 | 偏差 | §4 CLI status 输出在 argv 表外增加 mode/device/mtu/up 四行设备态（§3 响应字段对齐，缺键容错 unknown/false）；apply 成功响应非空 rolled_back 时追加 `undo:` 段 |
| 16 | 偏差 | §8 R2–R4 三步合流为单提交 1befbe7（多会话并行推进同条目，分步节奏让位于合并收口）；§7.1 REST/CLI 测试随其后的测试补齐提交落地（端点形状含 E10 503/E7 500/dry-run planned、CLI 参数与渲染纯函数） |

## 10. 风险与未决

- **O-global**：全局 `deny_unknown_fields` 的存量破坏面未量化（B2 剩余部分）——若未来收紧，先出 `rillanectl check --strict` 探路；
- **R-route1**：外部进程并发改路由（rillane 非系统唯一写者）——`replace` 语义 + apply 幂等重放可收敛，不做冲突检测；
- **R-route2**：clear 后数据面空转（TunIngress 仍在跑）——语义即所求，文档明示（§5）；
- **O-hot**：network 块热更新不支持（重启生效，对齐 P0-5 §1.6）；`route apply` 是运行期**路由层**重放，不等价于配置热更新（tun 块参数变更仍需重启）。
