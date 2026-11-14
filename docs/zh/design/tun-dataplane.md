# P1-1/P1-2 Linux TUN 真实现 + TunIngress 接线 runtime — 实现级设计

> 上游：[roadmap.md](roadmap.md) S2 · [networking.md](../networking.md) §3 目标形态 · [status-audit-tun-network-middleware.md](status-audit-tun-network-middleware.md) §5 实施影响（platform.rs 未编译/占位假写成功/挂载点缺失等核对结论均以该报告为准）。
> 本文是落地定稿：**设备接口、数据流、错误路径、测试策略、分步实施清单**。落地后偏差回填 §6。
> 复用基线：P0-1 会话语义（粘滞键/空闲回收/错误分类，**镜像而非调用**，见 §2.2）· P0-3 `EgressUdpConnector`/能力扫描 · TCP mesh 数据面（`mesh_transport`，既有）· `socket2`（已在 rillane-platform 依赖）· 注解匹配先例（`geoip.country`/`client.cidr`，`rillane-routing::matches_rule`）。

## 0. 范围与 P1-3 边界

| 在本条目内 | 归 P1-3 / 其他条目 |
|-----------|-------------------|
| `LinuxTunProvider`（真设备 I/O）+ 最小 `LinuxRouteManager`（addr/route 幂等 + 回滚） | `RillaneConfig.network` 配置区块 schema、`rillanectl route apply/clear` CLI、include/bypass 完整语义、全局接管（fwmark/ip rule/SO_MARK） |
| `TunIngress`（UDP NAT 面 + TCP 用户态栈面）、runtime 程序化接线（`RuntimeConfig.network_config`） | redir/transparent 模式（nftables/iptables） |
| 进程归因（best-effort，注解承载）+ `MatchCondition::Process` | DnsHandler 实现（P2-8）、PacketFilter 内核态实现（不存在，进程内规则即 §2.7 的 bypass 匹配） |
| Linux（含 OpenWrt musl 同路径） | Windows(Wintun)/macOS(utun)/Android/iOS（后续按本形状填空） |

软依赖：**UDP 经 mesh 链路**需 P0-4 `UdpChainRouter` 落地（S5）后才可用；**TCP 经 mesh 链路**用既有 `FlowOutputRouter::forward_chain` 即刻可用。P1-2 验收若以 UDP 游戏为对象，与 P0-4 同期；TCP 对象可先行。

## 1. P1-1 `LinuxTunProvider`

### 1.1 设备生命周期

- 打开 `/dev/net/tun`（`OpenOptions::new().read(true).write(true)` → `OwnedFd`）；
- `TUNSETIFF` ioctl（启用既有 optional 依赖 `nix`，features `ioctl`+`fs`，仅 `[target.'cfg(target_os = "linux")'.dependencies]`）：`ifreq` 填 `config.name`（`None` → 空名，内核分配 `tun%d`，`TUNGETIFF` 读回实际名）；flags = `IFF_TUN | IFF_NO_PI`——**纯 IP 包无 4 字节前缀**，与 `tun.rs::PacketInfo::parse_ip_header` 直接对齐；
- 单 fd（`IFF_MULTI_QUEUE` 归 V2）、非阻塞 + `tokio::io::unix::AsyncFd` 就绪循环；
- 销毁 = drop fd（内核自动回收接口）；MTU 取 `TunConfig.mtu`（默认 1500；游戏/QUIC 建议配置 1400，文档提示不强制）。

### 1.2 接口签名

```rust
// crates/rillane-platform/src/network/linux.rs（新增单文件，设计估约 400 行；落地现 1757 行含测试）
pub struct LinuxTunProvider {
    config: TunConfig,
    fd: Option<AsyncFd<OwnedFd>>,
    name: String,          // TUNGETIFF 读回
    up: bool,
    stats: InterfaceStats,
}
impl TunProvider for LinuxTunProvider {
    // create/destroy/up/down 按上节；configure_ip = ip addr replace；configure_routing 委托 LinuxRouteManager；
    // read_packet/write_packet = AsyncFd 就绪 + MTU 缓冲 + parse_packet_info / 整包写
    // configure_dns：MVP 直通（TunConfig.dns_servers 仅记录；DNS 劫持归 P2-8）
}
pub struct LinuxRouteManager { config: RoutingConfig, applied: Mutex<Vec<AppliedStep>> } // §1.3
```

**trait 裁剪（核对报告 A7 授权）**：删除 `TunProvider::packet_stream`、`TunPacketStream`、`TunInterface` 三者——占位的 `AsyncWrite` 假装成功并丢数据（`tun.rs:453-487`），不可保留；`packet_stream` 唯一消费者就是被删的流。trait 15 方法 → 14，语义稳定。

### 1.3 接口属性与系统路由（最小 `LinuxRouteManager`）

- **MVP 路由范围 = main 表显式路由（include 语义）**：只对纳入集（配置 CIDR / 进程规则配套端口段不可表达于路由层，仍走进程内）执行 `ip route replace <cidr> dev <tun> metric 0`。特定前缀天然优先于默认路由 → 流量入 tun；**不改默认路由**，rillane 自身出站连 relay 地址不受影响（relay 地址同时进 §2.7 auto-bypass 集）。**fwmark 逃逸面已落地（2026-10-05 出站 fwmark 批）**：`network.egress_fwmark` 配置 + 出站 TCP socket 统一 `SO_MARK`（`rillane_core::net_mark::connect_tcp`，缺省 0 零差异）+ apply 期 `ip rule fwmark` escape 表/逃逸规则（AppliedStep 回滚入账，EEXIST 容忍）——配置了 fwmark 时 apply 即使用 ip rule；默认路由改写的全局接管仍归 V2。
- 工具：`ip` 命令子进程（`tokio::process::Command`）。理由：Linux/OpenWrt 普适（busybox ip 子集够用）；netlink（`rtnetlink` crate）为 V2。注：这是仓库**首次库级写操作 shell-out**（既有先例仅 rillanectl diagnose 只读采集），见 §6 偏差 #2。
- **幂等**：`ip addr replace`/`ip link set up` 天然幂等；路由 `replace` 同。`AppliedStep` 日志记录已执行步骤；
- **回滚**：apply 中途失败 → 逆序撤销已执行步骤再 bail（启动失败不静默）；`clear_routing` = 逆序撤销全部 AppliedStep（P1-3 的 `route clear` 将复用同一机制）。

### 1.4 模块接线

- `network/mod.rs` 增 `#[cfg(target_os = "linux")] pub mod linux;`；四个工厂（`mod.rs:304-325`）由恒 Err 改为：tun/route 两工厂 `#[cfg(linux)]` 分派到 linux.rs、其余平台保留 Err；filter/dns 工厂保留 Err 并把错误信息指向"filter=进程内规则（本文 §2.7）/dns=P2-8"；
- `platform.rs` 死稿：维持未编译，头部加一行指向本文的注释（实施时落，本轮不动源码）；`nix` 死依赖就此启用。

## 2. P1-2 `TunIngress`

### 2.1 总体数据流

```
本机应用（socket 走 tun 路由）
   │ IP 包
   ▼ /dev/net/tun ──read_packet──► TunIngress 包循环（run）
   │ ① PacketInfo 解析（既有 tun.rs）+ IP/UDP/TCP 头编解码（§2.3 新增纯函数）
   │ ② bypass 匹配（BypassRule::matches + §2.7 auto-bypass 集）──命中──► 丢弃 + 计数
   ▼
TunFlowTable（§2.2：五元组 → 流条目）
   │ 首包：FlowContext{target, metadata.annotations[process.*]（§2.5）}
   │      → router.route（start() 注入的 flow_router()，chain 时即 RuntimeFlowRouter）
   │      → 决策粘滞缓存于流条目
   ├── UDP ──► connector.associate(ctx, &decision) → Arc<dyn UdpRelay>（P0-3：direct/ss/wg）
   │             │  send_to(payload) → 出站
   │             └ per-flow recv task：recv_from → 构造下行 IP/UDP 包（含校验和）→ write_packet → 应用
   └── TCP ──► smoltcp 用户态栈终结 TCP（§2.4）→ IoStream 适配 → Flow{io}
                 → output.forward(decision, flow)（FlowOutputRouter：单跳出站 / mesh 链路，既有）
```

### 2.2 `TunFlowTable`

```rust
struct TunFlowKey { proto: Proto, src: SocketAddr, dst: SocketAddr }   // Proto = Tcp|Udp
struct TunFlowEntry { decision: RouteDecision, relay: Option<Arc<dyn UdpRelay>>, // UDP 面
                      last_active: Instant, expiry: Instant }
struct TunFlowTable { map: DashMap<TunFlowKey, TunFlowEntry>, idle_udp/idle_tcp: Duration, max: usize }
```

- **镜像 P0-1 语义而非复用 `UdpSessionTable`**（裁决）：该表与 SOCKS5 控制连接/ASSOCIATE 准入语义绑定（DownlinkFull 队列挂在 associate、并发门、strict 源校验），TUN 无控制连接、源恒为本机 tun 地址，表形状更简；粘滞决策、空闲回收、`classify_failure` 错误分类（Timeout 族保映射 / Route 族拆映射重路由）这些**语义**逐条镜像；
- 空闲：UDP = `mapping_idle`（60s 同源）、TCP = `session_idle`（180s），懒清扫 + 每秒 sweep（与 P0-1 同构）；上界默认 4096，满员逐最早 expiry（同 P0-4 §3 R10 论证）；
- 下行未命中（表已过期/驱逐）→ 丢弃 + `unknown_flow` 计数（同 P0-4 语义）。

### 2.3 UDP 面细节

- 上行：`FlowTarget{host: dst.ip 字符串, port, proto: Udp}`（dst 为 IP 字面量，无域名解析环节）；
- associate 走 P0-3 `RoutingUdpConnector`（direct/ss/wg）；**决策为 `RoutePath::Chain` 时**：已随 **P0-4 S5 落地（2026-09）**统一换 `UdpChainRouter`（chain 决策 → mesh 桥，其余落 inner）——设计期所设"未接线前首包 bail"过渡态已随 S5 消失，本设计零改动兼容；
- **下行写回**（新纯函数，rillane-platform 内，单测钉住）：构造 `IP(dst=src.ip, src=dst.ip) + UDP 头 + payload`；IPv4 校验和可为 0 但 **IPv6 UDP 校验和强制**——统一实现真校验和（全量计算，约 20 行，golden vector 钉住）；IP id 自增、TTL 64、置 DF（不做分片）。

### 2.4 TCP 面：smoltcp 用户态栈

- 依赖假设：`smoltcp`（新依赖，版本实施时定；tun2proxy 成熟先例）；
- 模型：单个 smoltcp `Interface`（phy 层 = `LinuxTunProvider` 的 Rx/TxToken 适配器）承载全部连接，每 TCP 五元组一个 `TcpSocket`；smoltcp 对本机应用扮演"对端"（应答 SYN-ACK/ACK/窗口），**不监听**——本机 SYN 即主动接入；
- `SmolTcpStream`：smoltcp socket ↔ tokio `IoStream` 适配（双缓冲 + waker；实现 `rillane_core::IoStream`）；
- 交接：握手完成即 `Flow{id, target, io: Box::new(SmolTcpStream), metadata(+process 注解)}` → `output.forward(decision, flow)`，决策取自该流首 SYN 的粘滞缓存；
- 窗口/MTU：smoltcp 缓冲按 tun MTU−40−20；不启用 keep-alive（游戏长连接敏感）。

### 2.5 进程归因（best-effort）

- 时机：每流**首包归因一次**，`(src ip:port) → (pid, comm)` 缓存 TTL 30s；
- 方法：`/proc/net/{tcp,udp}` 取 inode → `/proc/<pid>/fd` 扫描（贵：仅当路由配置存在 `MatchCondition::Process` 规则时才做 fd 扫描，否则跳过）；netlink sock_diag 归 V2；
- 承载：annotation 键 **`process.name` / `process.pid`**（与 `geoip.country`/`client.cidr` 同族先例，`Flow::context()` 已透传 metadata，零结构体破坏）；
- 规则侧：`rillane-config` 增 `MatchCondition::Process { values: Vec<String> }`，`matches_rule`（`rillane-routing/src/lib.rs:494`）增臂读 `process.name` 注解（精确匹配 comm，或绝对路径后缀匹配，实施时二选一并钉测试）。

### 2.6 runtime 接线

- **所有权裁决**：`TunIngress` 是 TUN 模式的属主——内部组合 `LinuxTunProvider` + `LinuxRouteManager`（创建设备/设址/起路由在 `run()` 启动时完成，退出时 teardown），**不经 `NetworkManager`**（其通用容器形状面向其他模式；P1-3 [network-route.md](network-route.md) §2.2 已裁决不收编，TunIngress 属主延续）；
- 落点：`runtime_builder::build()` 在 UDP 块旁增 TUN 块——条件 `runtime_config.enable_network_virtualization && network_config.mode == Tun`，构造 `TunIngress` 插入 `ingress_endpoints["tun"]`；依赖仅 router + egress 描述符（UDP 连接器表与 `scan_udp_capability` **与 P0-3 UDP 块共享同一次构建结果**），无 build() 时序问题（不像 P0-4 §9.1——`run()` 时才取 `flow_router()`，start() 已统一注入 RuntimeFlowRouter）；
- `TunIngress: IngressEndpoint`：`run(self: Arc<Self>, router, output)` = 设备就绪门 → 包循环 + per-flow 任务族；与 socks5 入口同构，`start()` 的统一循环零改动。
- **与既有 ingress 的共存与选择边界**（P0-4 §1 同款缺口补全）：TUN ingress 与 socks5/mixed ingress 在 `ingress_endpoints` 中并列共存，两者**注入同一 `FlowRouter`**（chain 启用时即 `RuntimeFlowRouter`），共享 egress 连接器表与 `scan_udp_capability` 结果；**选择边界由内核/应用配置决定、不由 rillane 选择**——socks5 流量是应用显式走代理监听口，TUN 流量是系统路由把应用包导入 tun 设备，两路互不重叠（一个包不会同时进两个 ingress）；UDP 侧 TUN 流的 `Arc<dyn UdpRelay>` 归 `TunFlowEntry` 持有，**不注册进 P0-1 `UdpSessionTable`**（该表与 socks5 控制连接绑定），故 TUN 会话不计入 `rillane_udp_sessions_active`，见 §2.8。
- **TUN-only 启动已放行（2026-10-05 兑现，原 MVP 拒启约束撤销）**：`runtime_builder::validate()` 在 `ingress` 为空时仅当 `network.mode=tun` 且启用网络虚拟化放行——TUN 即入口（`build()` 注入 `ingress_endpoints["tun"]`，`start()` 同一循环 spawn，无常规入口特判）；其余空 ingress 仍拒（错误文案注记豁免面）。build 级钉子 `tun_only_config_builds_with_tun_as_sole_ingress`；TUN-only start 真机面未单独走查（与常规形态差异仅少 socks5 监听，start 循环同构）。

### 2.7 bypass 与防环

- **auto-bypass 集**（构建期自动，不需用户配置）：全部 egress `server`/`endpoint` 解析地址 ∪ mesh `listen_address` 与已注册 peer 地址 ∪ `control.api_bind` ∪ tun 自身网段——这些前缀**不写入** include 路由，且进进程内兜底名单；
- 默认 bypass：复用 `route.rs::default_bypass_rules()`（private_ip/loopback/multicast → Direct 语义 = 不进 tun）；
- 进程内兜底：包循环②处 `BypassRule::matches(dst_ip, iface)` 命中即丢 + 计数（路由层本不该放行，双保险）；
- 防环：include 显式路由模式下 rillane 出站 socket 走 main 表默认路由且目标已在 auto-bypass，天然无环。

### 2.8 指标（最小集，命名入 P0-5 `rillane_*` 家族）

`rillane_tun_packets_total{direction}`、`rillane_tun_bytes_total{direction}`、`rillane_tun_flows_active`、`rillane_tun_bypass_dropped_total`、`rillane_tun_parse_errors_total`、`rillane_tun_unknown_flow_total`、`rillane_tun_process_attr_miss_total`。原子量 + `/metrics` 渲染挂到 P0-5 §7 落点清单（该文档验收时一并出现）。
- **计量边界**：TUN 流量**不进 `rillane_udp_sessions_active`/`rillane_udp_relay_bytes_total`**——TunFlowTable 独立于 P0-1 `UdpSessionTable`（§2.2 镜像不复用）；P0-5 `rillane_udp_*` 序列仅反映 socks5 入站 UDP，TUN 的会话/字节只走本文 `rillane_tun_*` 家族。操作者勿把 TUN 有流量时 `rillane_udp_*` 为零误读为故障（两侧口径不同，分属两条序列族）。

### 2.9 smoltcp poll 驱动与下行注入（T4 主路径补全）

> 2026-09-30 六要素审计补全：R-tun1 标注 smoltcp 集成为 T4 主工作量，但 §2.4 只给了模型未给驱动机制——T4 无从下手，本节钉之。不发明 API：`Interface::poll`、phy `RxToken`/`TxToken`、tokio `Notify`/`Waker` 均为既有（假设，版本以 T4 实施时定，对齐 §6-1）。

- **单 poll 驱动点**：`TunIngress::run` 包循环每读一包 → IP 层判为 TCP → 喂 smoltcp phy 的 RxToken → `Interface::poll(&mut iface, Instant::now())` 一次；poll 产出的待发 IP 包经 phy TxToken 回写 `LinuxTunProvider::write_packet`；
- **下行注入**（egress → 应用）：egress 侧写 `SmolTcpStream`（`AsyncWrite`）→ 数据入 smoltcp socket 的 tx 缓冲 → **经 `tokio::sync::Notify` 唤醒 run 循环补一次 poll**，poll 生成含数据的 IP 段发往 tun。run 循环结构 = `select` 于 tun 读就绪 ∥ Notify；**不另起独立 poll 定时任务**（MVP——定时轮询会在空闲流上空转，读/写事件驱动已覆盖两个方向）；
- **waker**：`SmolTcpStream` 的 `AsyncRead`/`AsyncWrite` 在 socket 不可立即满足时登记 tokio waker，poll 推进状态后唤醒对应 `IoStream` 任务——无忙轮询（对齐 §2.4 双缓冲）；
- **背压**：smoltcp 窗口满 → `AsyncRead` 返回 Pending → egress 侧输出自然阻塞（与 socks5 TCP 流同语义，`FlowOutput` 已处理）；不启用 keep-alive（§2.4 游戏长连接敏感）。

## 3. 错误路径

| # | 错误点 | 条件/errno | 语义与恢复 |
|---|--------|-----------|-----------|
| E1 | 打开 `/dev/net/tun` | ENOENT | 报错附提示：`modprobe tun` 或容器需映射设备节点；启动失败 |
| E2 | 同上 | EPERM/EACCES | 明确提示需 CAP_NET_ADMIN（root/capabilities）；启动失败 |
| E3 | TUNSETIFF | EEXIST | `config.name=Some` 视为强制名 → 报错；`None` 不会触发（内核分配） |
| E4 | TUNSETIFF | EINVAL | flags/name 非法 → 程序缺陷，报错带 flags 值 |
| E5 | MTU 校验 | <68 | `TunConfig::validate` 既有检查（构建期） |
| E6 | `ip` 不可用 | NotFound | RouteManager 构建期探测 `ip -Version`，报错附 busybox 提示 |
| E7 | addr/route 执行失败 | 非零退出 | 逆序回滚 AppliedStep → bail（E7 含失败原因） |
| E8 | 读包 | EIO/EBADF | 设备已关/异常 → run 循环退出（ingress 终止语义） |
| E9 | 包解析 | 截断/未知版本/非首分片 | 丢弃 + `parse_errors` 计数；**ICMP 不支持**（MVP 丢弃+计数，PMTU 影响见 §7 O-icmp） |
| E10 | 流表满 | max | 逐最早 expiry 驱逐 + 计数（不拒新） |
| E11 | UDP associate/send_to 失败 | P0-3 各载体错误 | `classify_failure` 同关键词分类：Timeout 族保映射（MTU 类同 P0-3 裁决）；Route 族拆映射 → 下包重新决策 |
| ~~E12~~ | ~~UDP 链路决策~~ | ~~`RoutePath::Chain` 且 P0-4 未接~~ | **已失效（P0-4 S5）**——Chain 决策由 `UdpChainRouter` 承接（`build()` 以 `Some(bridge)` 包装并注入 TunIngress），"未接线前首包 bail"过渡态已随 S5 消失（§0 软依赖同步解除） |
| E13 | 下行未命中 | 表过期/驱逐 | 丢弃 + `unknown_flow` 计数 |
| E14 | TCP 握手 | 超时/RST | smoltcp socket 关闭 + 流表清理 |
| E15 | 进程归因 | proc 消失/权限 | `process.*` 注解缺省（Process 规则不匹配）+ `process_attr_miss` 计数，不报错 |
| E16 | 停止 | 陈旧 fd | down + destroy（fd drop）幂等；teardown 逆序回滚路由 |

## 4. 测试策略

### 4.1 单测（无特权，任何环境）

- IP/UDP 头编解码：roundtrip × v4/v6 × 上/下行 + **校验和 golden 向量**（v6 强制校验和、v4 置 0 与真值两态）+ 截断拒绝；
- `TunFlowTable`：空闲过期（MockClock，循 P0-1 测试形态）/上界驱逐/粘滞决策复用不重决策/错误分类拆映射重路由（关键词驱动）；
- bypass：`BypassRule` 匹配（既有逻辑补测）+ auto-bypass 集组装（含 egress/mesh/control 来源）；
- `MatchCondition::Process`：注解注入 → 匹配/不匹配两态；
- `ip` 参数组装：命令构造与执行分离，断言 argv 向量（不真执行）。

### 4.2 Linux 集成测试（`#[cfg(target_os = "linux")]` + 运行时 skip 守卫：无 `/dev/net/tun` 或无 CAP_NET_ADMIN → 打印 skip 返回，不算失败）

- 设备生命周期：创建（强制名/自动名读回）/up/addr/mtu 断言（`ip link show` 输出或 TUNGETIFF）；
- 路由：apply 幂等（重复执行）+ clear 完全还原 + 失败回滚（注入 cidr 冲突）；
- **P1-1 验收钉子「捕获 IP 包进入 FlowRouter」**：测试前缀路由入 tun → 本机 `UdpSocket` 发包 → mock `FlowRouter`（记录 FlowContext）断言五元组/target/`process.*` 注解；
- **UDP 全链路**：真设备 + mock `EgressUdpConnector`/`MockUdpRelay`（echo）→ 应用 socket 发 → **收 echo**（下行重组包校验和错误会被内核/应用丢弃，测试自验证）；【已落地 `tun_udp_e2e_capture_route_attribution_echo`，含捕获/路由/归因/echo】
- **TCP 全链路**：真设备 + smoltcp + mock `FlowOutput` echo（`FixedReportOutput` 同形）→ `TcpStream::connect(测试前缀地址)` 收发 echo——无需真实远端，mock 出口回环即验证全路径。【落地偏差：真设备集成测仅 UDP 一条；TCP 走无设备注入式单测（`tcp_full_path_echo_without_device`）+ `tun_tcp.rs` 单测，真设备 TCP e2e 未补】

### 4.3 门禁

- 单测套件无特权依赖（CI 常规跑）；集成套件 CI 需 rootful 或显式标注 skip；
- 全仓基线（P0-3 时点 118 项 + 后续 P0-4/P0-5 增量）零回归——本条目全部为增量，不改既有行为路径。

## 5. 分步实施清单（T0–T5）

依赖：`T0 → T1 → T2 → T3(UDP 面) / T4(TCP 面，仅依赖 T1) → T5`；T3/T4 可并行。提交节奏循 P0-4 §9.1.1：每步 build+test 全绿 → 单条 commit 引用本文 §节 → `git fetch origin main` + rebase → push → 下一步；禁 tag/release/force push。

| 步 | 内容与落点 | 依赖 | 验收 | 落地 |
|----|-----------|------|------|------|
| T0 | trait 裁剪（删 `packet_stream`/`TunPacketStream`/`TunInterface`）+ `network/linux.rs` 骨架 + 四工厂 cfg 分派 + nix 启用 | — | 编译绿；全仓基线持平；既有 rillane-platform 消费点零感知 | `c076fb8` |
| T1 | `LinuxTunProvider`：open/TUNSETIFF/AsyncFd 读写循环 + `PacketInfo` 联动 | T0 | 4.2 设备生命周期 + 「捕获 IP 包进入 FlowRouter」钉子（P1-1 验收核心） | `75c7747` |
| T2 | `LinuxRouteManager`：ip helper（构造/执行分离）+ addr/route 幂等 + AppliedStep 回滚 + auto-bypass 集 | T0（独立于 T1） | 4.2 路由幂等/还原/回滚 | `92f12ba` |
| T3 | UDP 面：头编解码纯函数 + `TunFlowTable` + `TunIngress` UDP 循环 + connector 接线 + build() TUN 块 | T1（+T2 供路由） | 4.1 编解码/流表 + 4.2 UDP 全链路 echo | `a9f11dc` |
| T4 | TCP 面：smoltcp 依赖 + Interface/phy 适配 + `SmolTcpStream` + Flow 交接 | T1 | 4.2 TCP 全链路 echo（mesh 链路 TCP 此步即可达；真设备 TCP e2e 见 §4.2 落地偏差注） | `b5785c2` |
| T5 | 进程归因 + `MatchCondition::Process` + §2.8 指标 + 文档回填（networking.md §2 现状节改写、todo 勾选、status-audit §4 修正清单执行） | T3+T4 | 进程/端口规则路由测试 + 指标序列可见 + P1-1/P1-2 验收全表核对 | `7a3024d`+`55e4f14`（回填 2/3；status-audit §4 已于 2026-10-04 文档对账轮补） |

验收对齐：P1-1 = T1+T2（+musl 交叉编译冒烟归 P3-3 打包）；P1-2 = T3/T4/T5——"按进程/端口规则将指定游戏流量路由至 mesh 链路"：TCP 对象 T4 即验；UDP 对象随 P0-4 S5；"bypass 默认安全" = T2 auto-bypass + 4.2 路由测试。

## 6. 偏差与假设（信息缺失处的自行假设均已注明）

| # | 类型 | 内容 |
|---|------|------|
| 1 | 假设 | smoltcp 为用户态 TCP 栈选型（仓库无先例；tun2proxy 先例），版本与 phy 适配细节实施时定 |
| 2 | 偏差 | `ip` 命令子进程为 MVP 接口操纵方式（Linux/OpenWrt 普适）；仓库首次库级写操作 shell-out；netlink 为 V2 |
| 3 | 假设 | MVP 路由范围 = main 表显式路由（include 语义）＋ fwmark 逃逸面（`SO_MARK` + `ip rule fwmark` escape 表，2026-10-05 落地）；默认路由改写的全局接管归 V2 |
| 4 | 裁决 | `IFF_NO_PI` 单 fd；multi-queue/TAP 归 V2 |
| 5 | 裁决 | 不复用 `UdpSessionTable`，镜像其语义（理由 §2.2） |
| 6 | 裁决 | 进程信息走 annotation（`process.name`/`process.pid`）而非 `FlowContext` 类型字段（先例 `geoip.country`；零破坏） |
| 7 | 裁决 | `TunIngress` 属主化设备+路由，不经 `NetworkManager`（§2.6）；`platform.rs` 维持未编译并加指向注释 |
| 8 | 偏差 | roadmap"3825 行"含未编译文件、S2"platform.rs 占位已是该形状"不成立——以 status-audit §4 为准回填 |
| 9 | 假设 | OpenWrt musl 同路径编译（std/tokio/nix 均 musl 兼容）；交叉编译产物验收归 P3-3 |
| 10 | 假设 | UDP-over-mesh 软依赖 P0-4；TCP-over-mesh 即刻可用 |
| 11 | 假设 | ICMP 不实现（丢弃+计数）；QUIC 即普通 UDP 透传（`TargetProto::Quic` 枚举保留不特判） |
| 12 | 偏差（落地登记） | TCP 监听句柄以 smoltcp「接生」代替字面「每五元组预建」——smoltcp 无按五元组预绑定 API（`tun_tcp.rs` §6 口径自注） |
| 13 | 偏差（落地登记） | smoltcp TCP socket 关闭 Nagle（`nagle_enabled=false`）——时延优先 |
| 14 | 偏差（落地登记） | `max_flows` 上限同口径限**新连接**：超限丢 SYN（不对既有流驱逐，与 UDP 面 E10 驱逐语义不同源） |
| 15 | 假设（落地登记） | TCP 栈面 IPv4-only：smoltcp 仅启用 `proto-ipv4` feature，IPv6 TCP 形不支持（`ipcodec.rs` 同口径自注）；UDP 面 v4/v6 均支持 |

## 7. 风险与未决

- **R-tun1（最大项，已消除）**：smoltcp 集成（phy 适配/waker/窗口调优）是 T4 主工作量——**T4 已落地 @b5785c2**（`tun_tcp.rs` SmolTcpStream 接管，回退路径未启用）；
- **R-tun2**：`/proc` fd 扫描成本——仅新流 + 仅存在 Process 规则时触发；采样与开关留实施期调；
- **R-tun3**：tun 全局接管场景下 rillane 自身控制面/metrics 回流——include 模式天然豁免；fwmark 逃逸面已落地（出站 socket `SO_MARK` + `ip rule fwmark` escape 表），默认路由改写的全局模式仍归 V2；
- **O-icmp**：ICMP（PMTUD/ping）不支持的补偿 = MTU 建议 1400；游戏场景是否需要 ICMP 透传待实测；
- **O-quic**：QUIC 流量是否需要识别为 `TargetProto::Quic` 参与规则（枚举已留）——MVP 不做，规则需求出现时再议；
- **O-netlink**：`ip` 命令 → rtnetlink 迁移窗口（P1-3 或 V2）。
