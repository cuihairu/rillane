# P1-1 Linux TUN 真实现 — 实现落定稿（T0–T2）

> 上游：[tun-dataplane.md](tun-dataplane.md) §1/§4/§5（设计定稿——设备接口、数据流、错误路径、测试策略、分步清单）。本文是其 **P1-1 半边（T0–T2）的实现对照文档**：TUNSETIFF 接口、包读写循环、`platform.rs` 占位替换方案、`LinuxRouteManager` 与测试落地实况，偏差回填 §6。T3+（`TunIngress` 包循环/UDP NAT/smoltcp TCP 面）归 P1-2；`network` 配置区块与 `seepctl route` 归 P1-3（[network-route.md](network-route.md)）。
> 落点：`crates/seep-platform/src/network/linux.rs`（单文件，T0 骨架起步，现 ~1170 行含测试）· 模块接线与四工厂 `network/mod.rs` · trait 裁剪 `network/tun.rs`。

## 1. 总览与提交锚点

| 步 | 内容 | 提交 | 设计对照 |
|----|------|------|---------|
| T0 | trait 裁剪（删 `packet_stream`/`TunPacketStream`/`TunInterface`，15→14 方法）+ `linux.rs` 骨架 + 四工厂 cfg 分派 + `nix` 启用 + `platform.rs` 死稿注记 | `c076fb8` | §1.2/§1.4 |
| T1 | `LinuxTunProvider`：open/TUNSETIFF/TUNGETIFF/AsyncFd 读写循环 + `PacketInfo` 联动 + 捕获钉子集成测 | `75c7747` | §1.1/§1.2 |
| T2 | `LinuxRouteManager`：ip helper（构造/执行分离）+ addr/route 幂等 + `AppliedStep` 回滚 + auto-bypass 半边 | `92f12ba` | §1.3 |

依赖关系与提交节奏按设计 §5：T0 → T1 → T2（T2 仅依赖 T0）；每步 build+test 全绿后单条 commit。

## 2. 设备生命周期与 TUNSETIFF 接口（T1）

### 2.1 创建时序

`create_interface`（`linux.rs:315`）幂等（fd 已持有即 `Ok`，E16 同口径），按序五步：

```text
① open /dev/net/tun（open_tun_file，linux.rs:198）
     ENOENT   → E1：报错附「modprobe tun / 容器映射设备节点」
     EPERM/EACCES → E2：报错附「需 CAP_NET_ADMIN（root/capabilities）」
② build_iff_request（linux.rs:42）——ifr_name 按给定名（空名 = 内核分配 tun%d），
     flags 固定 IFF_TUN | IFF_NO_PI；名长 ≥ IFNAMSIZ(16) 早期拦截（E4 前置防线，
     免走一次注定 EINVAL 的 ioctl）
③ tun_set_iff（TUNSETIFF，_IOW('T',202,int)——nix ioctl_write_ptr_bad 宏，linux.rs:37）
     errno 映射（map_tunsetiff_err，linux.rs:215）：
       EEXIST → E3（config.name 强制名冲突；None 内核分配不触发）
       EPERM/EACCES → E2（CAP_NET_ADMIN）
       EINVAL → E4（flags 非法 = 程序缺陷，报错带 flags 值）
④ tun_get_iff（TUNGETIFF）读回实际接口名——内核为名的唯一事实源
     （ifreq_name 取 NUL 结尾串；读回空名视为内核状态异常报错）
⑤ F_SETFL O_NONBLOCK（AsyncFd 就绪语义要求）→ File 转 OwnedFd → AsyncFd 注册
```

**为什么 TUNGETIFF 而非沿用请求名**：`TunConfig.name` 是 `Option<String>`，`None` 时内核分配 `tun%d`，请求缓冲里没有这个名字；且即便强制名，读回也是防御性核对（测试周期 A/B 两态分别钉住，§7.2）。

### 2.2 销毁与幂等

- `destroy_interface`（`linux.rs:349`）= `fd.take()` → drop fd → 内核自动回收接口（E16 幂等：未创建时 `Ok`）。集成测以 `ip link show dev <name>` 非零退出断言接口确已消失；
- `up`/`down`/`configure_ip` 幂等性来自 `ip` 命令本身（`set`/`replace` 语义，§2.3）。

### 2.3 接口属性：`ip` 命令 shell-out 与构造/执行分离

- **构造/执行分离**（§4.1 测试要求「断言 argv 向量（不真执行）」）：`ip_argv_link_up/link_down/addr_replace/route_replace/route_del/addr_del/link_down_name`（`linux.rs:76-195`）只拼 argv；执行统一走 `run_ip`（`linux.rs:115`）——
  - E6：`NotFound` → 报错附「需 iproute2 或 busybox ip」；
  - E7：非零退出 → 带 stdout/stderr 上抛（启动失败不静默，撤销前信息完整）；
- `up_interface` 把 up 与 MTU 合一条命令（均幂等），MTU 取 `TunConfig.mtu`（默认 1500）；`configure_ip` = `ip addr replace <cidr> dev <name>`，v4 掩码缺省 /32、v6 prefix 缺省 /128（单机假设；`ipv4_gateway` 不在此消费——默认路由/网关接管归 P1-3/V2）；
- `configure_dns` MVP 直通（`dns_servers` 仅记录，DNS 劫持归 P2-8）；`configure_routing` 在 provider 上保持 **Err 委托点**（`linux.rs:396`）——设备+路由属主是 `TunIngress`（设计 §2.6/§6-7 裁决），provider 不自带路由。

## 3. 包读写循环（T1）

### 3.1 上行 `read_packet`（`linux.rs:409`）

```text
loop {
  guard = fd.readable().await              // AsyncFd 就绪等待
  buf = vec![0; mtu]                        // MTU 缓冲按 config.mtu
  try_io(nix::unistd::read)                 // EAGAIN → 转 WouldBlock
  ├─ Ok(0)         → continue               // 0 字节非包，回 readable 等待
  ├─ WouldBlock    → continue               // readiness 已清，重等
  ├─ Err(e)        → receive_errors++ → Err // E8：设备已关/异常，错误上抛
  │                                          //（ingress 运行时即终止语义）
  └─ Ok(n)         → buf.truncate(n)
       parse_tun_packet(buf)
       ├─ Err  → receive_errors++ → continue // E9：坏包丢弃计数，不中断读流
       └─ Ok   → packets/bytes_received++ → 返回 (Bytes, PacketInfo)
}
```

要点：**E8 与 E9 的分流**是循环的生命线——真错误（EIO/EBADF）终止流，坏包（截断/未知版本）只计数继续；link up 后内核可能注入无关包（如 IPv6 RS），由上层按五元组筛（§7.2 捕获钉子即此形态）。

### 3.2 下行 `write_packet`（`linux.rs:453`）

同构的 `writable().await` + `try_io(write)` 循环；差异在完成判定：**TUN 包面向写，部分写不应发生**——`n == packet.len()` 才计数返回，短写按程序缺陷报错（`send_errors++`），不做拆包重试。

### 3.3 TUN 包解析：IFF_NO_PI 对齐（`parse_tun_packet`，`linux.rs:235`）

`IFF_TUN | IFF_NO_PI` 输入是**纯 IP 包**——无以太网头、无 4 字节 PI 前缀。故不复用 `parse_packet_info`（其以太网猜测路径会把 src IP 前两字节当 ethertype 误判），而是首 nibble 定版本 → `PacketInfo::parse_ip_header`；空包/截断/未知版本拒绝（v4/v6 golden 向量钉住，§7.1）。

## 4. platform.rs 占位替换方案（T0 接线）

替换是**三层收口**而非改写 `platform.rs` 本身：

| 层 | 动作 |
|----|------|
| trait（`tun.rs`） | 裁剪删除 `TunProvider::packet_stream`（15→14 方法）与 `TunPacketStream`/`TunInterface`——占位的 `AsyncWrite` 假装成功并丢数据，不可保留；`packet_stream` 唯一消费者就是被删的流（设计 §1.2，核对报告 A7 授权） |
| 工厂（`mod.rs`） | 四工厂由恒 Err 改 cfg 分派：`#[cfg(target_os = "linux")] pub mod linux;`，tun/route 两工厂 Linux 返回真实现、其余平台保留 Err；filter/dns 恒 Err 改口径——filter=进程内规则（§2.7）/dns=P2-8。分派是唯一事实源：`create_tun_interface` 便捷函数改委托工厂，不再自带恒 Err 占位 |
| 死稿（`platform.rs`） | 维持未编译（不在模块树），头部加指向注记：真实现按 tun-dataplane.md §1.4 落在 `linux.rs`，其 `packet_stream` 签名随 trait 裁剪已过时，勿据此恢复 |

依赖面：`nix` 移入 `[target.'cfg(target_os = "linux")'.dependencies]`（features `ioctl`+`fs`）；tokio 增 `process` feature（`ip` 子进程）。既有消费点零感知——seep-runtime 仅经四工厂，`enable_network_virtualization` 缺省 false 不触达。

## 5. LinuxRouteManager（T2）

### 5.1 `AppliedStep`：幂等与撤销的事实源

```rust
pub enum AppliedStep {                       // linux.rs:493
    AddrReplaced { interface, cidr },        // ip addr replace ↔ 撤销 = addr del
    LinkUp { interface },                    // ip link set up ↔ 撤销 = link down
    RouteReplaced { cidr, interface, metric },// ip route replace ↔ 撤销 = route del
}
```

apply/clear 读写 `applied: Mutex<Vec<AppliedStep>>`；`Display` impl 供 `remove_route` 按名查找。幂等靠 `ip` 的 `replace` 语义；**"完全还原" = 撤销 seep 所加步骤**（P1-3 §5 同口径），非快照回滚。

### 5.2 apply / clear / 回滚（`linux.rs:706/801`）

- `apply_routing`：`enabled=false` 短路 → 地址步骤（`tun_config` 存在时，与 provider 的 `configure_ip` 重复 replace 幂等无害——兼容 RouteManager 独立使用）→ 规则按 **priority 升序**逐条：disabled 跳过、auto-bypass 命中跳过（debug 日志带名）、接口名缺省回落 `interface_name`（缺则报错）；
- **中途失败回滚**：单条失败 → 本次 `temp_applied` 逆序撤销（addr del/route del）→ `Err(e.context("…已回滚"))`——E7 报错含失败原因与回滚事实；全部成功才合并 `applied`（失败不留半套状态）；
- `clear_routing` = `rollback_all`：逆序撤销全部步骤，尽力而为不因单步失败中断；
- 单条操作：`add_route`（auto-bypass 命中直接 Err 拒绝写入）/ `remove_route`（按名查找 applied 取出并 del）/ `modify_route`（删后加）/ `enable_route`（true 重 apply / false remove）；查询面 `get_routing_table`/`lookup_route` 从 `applied` 重建（无系统读回，MVP 口径）。

### 5.3 auto-bypass 集（现状与接缝）

`compute_auto_bypass`（`linux.rs:529`）现收集 **tun 自身网段**（`ipv4_addr+netmask` / `ipv6_addr+prefix`）；egress server/endpoint、mesh listen/peer、control.api_bind 地址**留运行时注入**（`RoutingConfig` 静态字段不含这些来源，TODO 占位在码内注明）——全集组装随 T3（TunIngress 属主）与 R1（build 接线）落地，届时本函数收敛为「静态半边」。默认 bypass（private/loopback/multicast）以进程内 `BypassRule` 匹配为准，不进 CIDR 集（设计 §2.7 双保险的进程内侧）。

### 5.4 锁与异步：MutexGuard Send 问题

`std::sync::Mutex` 的 guard 非 `Send`，跨 `.await` 持锁编译不过——`rollback_all`/`remove_route` 先 **drain/remove 取出步骤释放锁再 await** 执行 `ip` 命令（`linux.rs:642-645/832-841`）。锁只护 `Vec` 读写，不护子进程执行。

## 6. 偏差与实现裁量（对照 tun-dataplane.md）

| # | 类型 | 内容 |
|---|------|------|
| 1 | 偏差 | 设计 §1.3-E6 说「RouteManager 构建期探测 `ip -Version`」——实现为**首次 `run_ip` 时 NotFound 即时报错**（E6 语义不变，免一次预备进程派生） |
| 2 | 增补 | `build_iff_request` 对名长 ≥ IFNAMSIZ(16) **早期拦截**（设计未提；E4 的前置防线，单测钉 15/16 字节边界） |
| 3 | 增补 | `read_packet` 对 **0 字节读** continue（非包语义）；`write_packet` 对**短写**按程序缺陷报错不重试（TUN 包面向写） |
| 4 | 增补 | `parse_tun_packet` 独立函数 + 首 nibble 定版本——设计 §1.1 只说「与 `parse_ip_header` 直接对齐」，实现显式绕开 `parse_packet_info` 的以太网猜测并注明误判风险 |
| 5 | 缺口 | `compute_auto_bypass` 仅静态半边（tun 网段），egress/mesh/control 地址未收集——设计 §2.7 全集随 T3/R1 补（码内 TODO 注明），**R0 转换层（seep-runtime network_config.rs）已做同语义剔除**，两侧合流于 R1 |
| 6 | 缺口 | `monitor_changes` 恒 Err（`RouteManager` trait 方法，MVP 无路由监控需求；设计未列） |
| 7 | 裁量 | 接口名注入式：`LinuxRouteManager::set_interface_name`（TUNGETIFF 读回后由属主注入），非构造期传入——`TunConfig.name` 是 Option，创建前无名 |
| 8 | 维持 | `configure_routing` 在 provider 上保持 Err 委托点（设备+路由属主 = TunIngress，§2.6 裁决不改） |
| 9 | 维持 | musl 同路径编译为假设（§6-9），交叉产物验收归 P3-3 |

## 7. 测试计划与落地实况

### 7.1 单测（无特权，任何环境；§4.1）

| 测试 | 钉住 |
|------|------|
| `iff_request_build_and_readback` | ifreq 构造/读回往返；flags 值断言；空名全零；**15/16 字节名长边界** |
| `netmask_prefix_conversion` | 点分掩码 → 前缀四档（/0、/16、/24、/32） |
| `ip_argv_constructors` | link up（含 MTU）/down/addr replace 逐 argv 断言（**构造/执行分离**的可测面；route_replace/del 等同族函数同构覆盖） |
| `parse_tun_packet_v4_udp_golden` | 最小 IPv4(20B)+UDP 头 → src/dst IP、端口、proto=17、长度、is_udp |
| `parse_tun_packet_v6_and_rejects` | IPv6+TCP 头 → 端口/proto=6；拒绝面：空包/截断/未知版本带原值 |
| `linux_tun_and_route_factories_dispatch`（mod.rs） | cfg(linux) 下 tun/route 工厂分派真实现 |
| `filter_and_dns_factories_stay_err`（mod.rs） | filter/dns 恒 Err 口径（「进程内规则」/「P2-8」文案钉住） |

### 7.2 Linux 集成测（§4.2：运行时 skip 守卫）

`device_lifecycle_and_capture`（`linux.rs:1052`）——守卫双点：`tun_device_available()`（无 `/dev/net/tun` → 打印 skip）/ `is_permission_skip`（错误链含 CAP_NET_ADMIN → skip）；**skip 不算失败**，CI 无特权环境零影响：

- **周期 A（强制名）**：`seepT1<pid>` 创建 → 名读回断言 → up/addr/mtu 经 `ip addr|link show` 读回断言（10.66.0.1/24、mtu）→ **捕获钉子（P1-1 验收核心，provider 半边）**：bind `10.66.0.1:0` 的 `UdpSocket` 发往 `10.66.0.2:9999` → 内核经 connected 路由注入 tun fd → `read_packet` 循环筛目标五元组（先发后读，tun 队列缓冲不丢；非目标包忽略）→ src/dst IP+port、proto、长度、载荷尾、收包计数全断言 → down/destroy → `ip link show` 断言接口已被内核回收；
- **周期 B（自动名）**：`TunConfig::default()`（name=None）创建 → 读回名 `tun%d` 形式断言 → destroy。

「捕获 IP 包**进入 FlowRouter**」的 FlowRouter 半边（mock router 记录 FlowContext）随 T3 `TunIngress` 落地——provider 半边已实证包能从内核进到 `read_packet` 返回值，剩余是 ingress 循环的接线测试（设计 §4.2 钉子原句）。

### 7.3 门禁与基线

- 单测套件无特权依赖（CI 常规跑）；集成套件 skip 守卫保证非 root CI 零失败；
- 落地时点全仓基线：T0/T1 各 172 项（170+2），T2 起 172 项持平；后续 P1-3 R0 / P1-4 M0 增至 200 项（2026-10-01 时点），全部增量零回归。

## 8. 与 P1-2/P1-3 的接缝

- **P1-2（T3/T4/T5）**：`TunIngress` 属主化 `LinuxTunProvider`+`LinuxRouteManager`（创建/设址/起路由在 `run()` 启动时完成，退出 teardown）；`read_packet` 返回的 `(Bytes, PacketInfo)` 即包循环输入；auto-bypass 全集在其组装（§5.3）；
- **P1-3（R1+）**：`network` 块 → `TunConfig`/`RoutingConfig` 转换已落 `seep-runtime/src/network_config.rs`（R0，含 auto-bypass 剔除半边）；`seepctl route apply/clear` 复用 `apply_routing`/`rollback_all` 同一机制（幂等/完全还原/失败回滚三口径一致）。
