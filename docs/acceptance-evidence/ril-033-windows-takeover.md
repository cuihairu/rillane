# RIL-033｜Windows 接管/旁路实现——真机证据

- **实机日期**：2026-11-21 10:40–11:34（+08:00；各段输出来自实跑，时间戳见文末 AFTER 段）
- **证据机**：`imac`（ssh 直达，用户 `imac\cui`，SSH 会话完整性 High Mandatory Level——管理员等效；主机名 `IMAC`）
- **交付物**：`crates/rillane-platform/src/network/win_tun.rs`（Wintun 用户态封环 FFI + `CapturePort` 实现）、`win_net.rs` 机批次扩展（`connect_escape_tcp`、`adapter_if_index`、快照 v6 面）、`examples/win_probe.rs`（验收序列探针）
- **探针部署**：Linux 交叉编译 `x86_64-pc-windows-gnu`（release）→ scp `probe.exe` + 官方构建 `wintun.dll`（0.14.1 `bin/amd64`，427552 字节，与 exe 同目录，`LoadLibraryW` 默认搜索路径命中）→ imac `C:\Users\cui\ril033\` 管理员会话实跑
- **捕获网段**：RFC 5737 TEST-NET-2 `198.51.100.0/24`（适配器 `198.51.100.1/32`、目标 `198.51.100.2`）。**首跑用 `198.18.0.0/24`，后改段**——`198.18.0.0/15` 基准保留段正被同机另一会话占用（`wg-meshlet-probe` 隧道 2026-11-21 11:18:25 新建，`Temp\meshlet\` 实证）；换段不影响任何结论，只避免并发冲突。

## 1. 选型事实：wireguard-nt 无用户态包 IO → Wintun 封环

wireguard-nt 是**纯内核实现**——官方 API 仅适配器管理面
（`WireGuardCreateAdapter/SetConfiguration/SetAdapterState` 等 11 个导出），
文档原话 *"No send/receive functions exist in this API... all tunnel packet
I/O is performed by the NT kernel driver itself"*。rillane 数据面需要在
用户态读包进代理栈，故 Windows TUN 等价物只能是 **Wintun**（0.14 用户态
封环 API：`CreateAdapter/StartSession/ReceivePacket/SendPacket`）。本批
FFI 面（`win_tun.rs`）动态解析全部 12 个导出（`LoadLibraryW` +
`GetProcAddress`，任一缺失即报错——不引 windows-sys/winapi 依赖），
wintun.h 0.14.1 签名逐一比对。

## 2. 真机事实（全部实跑得出，错误样本在注释里点名）

| # | 事实 | 实证 |
|---|------|------|
| F1 | **`WintunGetAdapterLUID` 返回的 LUID 低 24 位（If 索引位）为 0**——新建适配器上直接派生 If 索引会得到 0，`route add … if 0` 被 route.exe 拒绝（`指定的接口不存在`，退出 1）。If 索引必须取 **OS 权威口径**（`netsh interface ipv4 show interfaces` 按适配器名查，`win_net::adapter_if_index`） | `DIAG-LUID OK luid=0x0035008001000000 if_index=0` + `DIAG-NETSH OK netsh_row=Some(WinIfInterface { if_index: 65, name: "rillane-probe" })`；随后 `route add` 以 if 65 成功 |
| F2 | **驱动版本在 `LoadLibrary` 后读为 0x00000000**（LastError=2 FILE_NOT_FOUND），**`StartSession` 后才被填充**——版本判定必须放在会话开后，加载期判 0 不是失败 | `P1-LOAD OK … driver_version_at_load=0x00000000` → `P1-DRIVER OK running_driver_version=0x0000000E`（0x0E = 0.14 版本编码） |
| F3 | **route.exe 把 `300.300.0.0` 逐字节模 256 后静默建路**（不拒绝非法目的）——事务补偿测试的坏步必须用真实被拒输入（接口 0 实证被拒），否则 apply 不失败、补偿路径根本不被触发 | 首跑 `P4-COMPENSATE FAIL bad step failed=false`（300.300.0.0 被接受）→ 改 `interface_index: 0` 后 `P4-COMPENSATE OK bad step failed=true` |
| F4 | **下行注回的 TCP ack 必须认领已收字节**：照抄 `seg.ack_seq`（SYN-ACK 确认点）会 ack 到客户端未发送的序号，Windows 按 RFC 5961 丢弃我方段——真机症状是握手成、请求到、响应永远不到（curl `http_code=000`） | 首跑 `P2b-REALHTTP FAIL … curl_http_code=000` → `ack = seg.seq + payload.len()` 修复后 `P2b-REALHTTP OK … curl_http_code=200` |
| F5 | **/32 适配器地址 + 网关=自身地址**（`198.51.100.1/32`，路由网关同值）→ L3 点对点、无 ARP 歧义，真实应用流被内核直接送入封环（RIL-032 wgprobe 同形） | P2/P2b 全过；`route add 198.51.100.0 mask 255.255.255.0 198.51.100.1 metric 5 if 66` 实跑成功 |
| F6 | **主机无 v6 默认路由**（`route print -6` 无 `::/0`）→ `escape_bind_ip_v6()` 如实返回 `None` 不猜；v4 出口身份 `192.168.5.117` | `P0-SNAPSHOT OK primary=Some("192.168.5.117") escape_bind=192.168.5.117 v6_default_routes=0 v6_identity=None` |

## 3. 验收映射（todo RIL-033 验收原文 → 探针段）

```
PROBE P0-SNAPSHOT OK primary=Some("192.168.5.117") escape_bind=192.168.5.117 v6_default_routes=0 v6_identity=None
PROBE P1-LOAD OK wintun.dll loaded, driver_version_at_load=0x00000000
PROBE P1-ADAPTER OK if_index_os=66 if_index_luid=0 addr_set=true
PROBE P1-DRIVER OK running_driver_version=0x0000000E (0.14 = 0x00140000 风格编码)
PROBE P2-ROUTE OK capture route up: 198.51.100.0/255.255.255.0 if 66
PROBE P2-REALFLOW OK icmp_requests=2 udp_captured=true replies(TTL=)=1 stats=(3, 0) (ping: real app via kernel stack; reply injected downlink)
PROBE P2b-REALHTTP OK segments=3 syn_ack=true get_seen=true http_sent=true curl_http_code=200
PROBE P3-ESCAPE-UDP OK bind=192.168.5.117 -> 223.5.5.5:53 real A query answered=true
PROBE P3-ESCAPE-TCP OK connect_escape_tcp(192.168.5.117) connected 223.5.5.5:53 local==bind=true
PROBE P4-COMPENSATE OK bad step failed=true good step auto-undone (route absent=true) rollback idempotent=true
PROBE P5-CLEANUP OK adapter absent=true, route deleted
PROBE OVERALL OK all sections passed
```

### 「真实浏览器/游戏流进入共享内核」→ P2 + P2b

- **P2（ICMP + UDP）**：系统 `ping.exe`（真实外部应用，内核 TCP/ICMP 栈产出）
  打 `198.51.100.2` → 捕获网段路由把流送进封环：**环内收到 2 个真实 ICMP
  echo request**（`icmp_requests=2`），用户态字节手术（type 8→0、IP 源目
  互换、IP/ICMP 校验和重算）回注下行 → **ping.exe 打印 Reply（TTL=）1 次**
  ——下行注入被内核消费。同段进程内 UDP 数据报原文入环（`udp_captured=true`）。
  端口用量 `stats=(3, 0)`：捕获 3 包（2 ICMP + 1 UDP），解析失败 0。
- **P2b（完整 HTTP 事务）**：Windows 内置 `curl.exe`（真实 TCP/IP + HTTP 栈）
  连 `http://198.51.100.2:80/` → 封环收到真实 SYN / ACK / GET 三段；
  探针在用户态完成三次握手（`build_tcp_packet` 真校验和）+ 200 应答
  （`Content-Length` 分界 + `Connection: close`）→ **curl 自报
  `http_code=200`**——整事务经共享内核闭合，非探针伪造。

### 「DNS/代理拨号不循环」→ P3

- **UDP 旁路**：出站 socket 显式 bind 物理口 IP `192.168.5.117`
  （`win_net::bind_escape_udp`，RIL-032 实证原语）→ 真实 A 查询
  （手编码最小 DNS 报文）发公网解析器 `223.5.5.5:53` → **应答可读**。
- **TCP 旁路**：`win_net::connect_escape_tcp`（socket2 先 bind 后 connect，
  RIL-033 机批次接入面）→ 连 `223.5.5.5:53` 成功且
  **`local_addr().ip() == 192.168.5.117`**——拨号钉在物理口，未被 TUN 吸走成环。
- 同期捕获网段路由在位（198.51.100.0/24）——旁路面与接管面并存时不循环。

### 「失败可补偿」→ P4

`WinRouteTransaction::prepare` 好步（`198.51.100.0/24` if 66）+ 坏步
（同形状、`interface_index: 0`——真机实证被拒输入，见 F3）→ `apply()`
遇坏步**失败**（`bad step failed=true`）→ **自动逆序补偿**：好步已建的
路由被撤销，`route print -4` 复核 `route absent=true` → `rollback()`
连调两次均成功（幂等，missing-as-undone）。

## 4. 清理（幂等、不遗留）

探针 P5：显式 `drop(port)`（EndSession）→ `drop(device)`（CloseAdapter）
→ `cleanup_quiet()`（`route delete 198.51.100.0 mask 255.255.255.0` 按目的
+掩码撤，**不依赖适配器仍在**——CloseAdapter 后按名查 If 索引会漏删路由，
这是首版清理路径的泄漏面）→ `adapter absent=true, route deleted`。

独立复核（2026-11-21 11:34:42）：

```
rillane-probe adapters: 0 (expect 0)
198.51.100.0/24 routes: 0 (expect 0)
198.51.100 routes in route table: 0 (expect 0)

Name                              Status
----                              ------
WireGuardManager                 Stopped
WireGuardTunnel$wg-meshlet       Running
WireGuardTunnel$wg-meshlet-probe Stopped
```

 WireGuard 既有服务全程未被本探针触碰（首跑 11:12 与 11:24 两次
`BEFORE`/`AFTER` 快照均含 `WireGuard*` 服务状态；期间其状态变化来自
同机另一会话，与本批无关——见 §5）。

## 5. 并发与边界（诚实注记）

- **同机并发**：实机时段另一会话在操作 WireGuard 隧道（`wg-meshlet-probe`
  11:18:25 新建、`WireGuardTunnel$wg-meshlet` 一度 Stopped 后 11:30 复原
  Running）。本探针只创建/删除自己的 `rillane-probe` 适配器与
  `198.51.100.0/24` 路由，未触任何 `wg*` 资源；捕获段为此从
  `198.18.0.0/24` 改 `198.51.100.0/24`（不与 `198.18.0.0/15` 基准保留段交叠）。
- **OS-free 决策层**（`win_takeover.rs`，首段交付）的回归在 Linux 验证席
  确定性完成（模块 13 测 + 真机文本形状夹具）；本批真机面只覆盖
  `win_tun.rs`/`win_net.rs` 扩展与探针序列。
- **DNS 劫持未在本批实测**：`WinAppliedStep::DnsHijack`（netsh
  dnsservers 形状）的 argv/undo 往返在 OS-free 层单测覆盖；真机改 DNS
  会动用户网络配置，与本机并发会话冲突风险高——真机 DNS 劫持端到端
  留待独占时段补测（不影响「DNS/代理拨号不循环」验收：该项验的是
  **旁路拨号不进环**，P3 已闭环）。
- **wireguard-nt 面**（内核加密隧道对接）不在本批交付——选型事实见 §1，
  与 RIL-032 证据「wireguard-nt 为主、Wintun 兼容为目标」的分层一致：
  接管数据面用 Wintun，隧道加密面是上游对接的独立层。
