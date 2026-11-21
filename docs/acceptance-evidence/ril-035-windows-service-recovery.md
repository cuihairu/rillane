# RIL-035｜Windows 服务与退出恢复——真机证据

- **实机日期**：2026-11-21 15:55–16:03（+08:00；净场单跑 16:03:27–16:03:39，输出全实跑，原文见文末段）
- **证据机**：`imac`（ssh 直达，用户 `cui`，SSH 会话 High Mandatory Level——管理员等效；主机名 `IMAC`）
- **交付物**：`crates/rillane-platform/src/network/win_service.rs`（真机 SCM FFI：advapi32 动态解析客户端——安装/启动/停止/卸载/失败动作/QueryServiceStatusEx 含 dwProcessId；服务端——调度器/HandlerEx/状态回报）、`examples/win_service_probe.rs`（服务主体 + 编排验收序列）
- **探针部署**：Linux 交叉编译 `x86_64-pc-windows-gnu`（release）→ scp `probe.exe`+`wintun.dll` 到 imac `C:\Users\cui\ril035\`，`run.ps1` 编排（管理员会话实跑 + 签名/驱动独立记录）

## 1. 验收映射（todo RIL-035 验收原文 → 探针段）

| 验收项 | 探针段 | 实跑输出 |
|---|---|---|
| 服务崩溃 | P3 | `taskkill /F /PID 82108`（按 pid，勿 /IM——服务自身就是 probe.exe）→ SCM 失败动作自动重启 → 重启**不带参** → `SVC RECOVER undone=1` 撤销崩溃前路由 → 路由消失 |
| 切网 | P5 | 路由在位 → 模拟丢失（route delete）→ `DefaultRouteChanged` 事件 → `action=reassert_routes` 幂等重放 → 路由回位 |
| 卸载 | P4+P7 | 停止→`DeleteService`→名号消失；适配器 CloseAdapter 移除、路由撤、账本清空 |
| 休眠 | 具名缺口 | 见 §4（与切网收敛同一重放机制；真机 suspend 实测因共享主机不打扰同租户留待独占窗口） |
| 签名/依赖限制公开 | run.ps1 + P6 | `probe.exe: NotSigned` / `wintun.dll: Valid`（Get-AuthenticodeSignature）；wintun KERNEL_DRIVER 在册 + `running_driver_version=0x0000000E`（0.14） |

```
PROBE P0-BASELINE OK service_absent=true route_absent=true adapter_absent=true
PROBE P1-SCM-INSTALL OK service_registered=true start_type=demand failure_action=restart(5s) image="C:\Users\cui\ril035\probe.exe"
PROBE P2-ADAPTER OK if_index_os=42 if_index_luid=0 addr_set=true session_up=true
PROBE P3-CRASH-RECOVER OK running=true route_up=true journaled=true svc_pid=82108 killed=true restarted=true recovered_route_absent=true log_recover=true
PROBE P4-STOP-UNINSTALL OK stopped=true deleted=true route_absent=true journal_empty=true
PROBE P5-NETCHANGE-REASSERT OK up_before=true gone_after_loss=true action=reassert_routes reasserted=true recover_undone=1 clean=true
PROBE P6-DRIVERS OK running_driver_version=0x0000000E (0.14 风格编码) sc_query_wintun=true
PROBE P7-CLEANUP OK adapter_absent=true route_absent=true service_absent=true journal_empty=true
PROBE OVERALL OK all sections passed (8 sections)
PROBE EXIT=0
```

服务日志（`C:\ProgramData\ril035\svc.log`，单跑）：

```
SVC START args=["apply-route", "198.51.100.0", "255.255.255.0", "198.51.100.1", "9999", "42"]
SVC RECOVER undone=0 already_gone=0 failed=0 snapshots_restored=0 snapshots_skipped=0
SVC APPLY-ROUTE OK
SVC BODY DONE idle-until-stop
SVC START args=[]                    ← SCM 崩溃自动重启：不带参
SVC RECOVER undone=1 already_gone=0 failed=0 snapshots_restored=0 snapshots_skipped=0   ← 撤销崩溃前路由
SVC BODY DONE idle-until-stop
```

## 2. 真机事实（F12–F15）

| # | 事实 | 实证 |
|---|---|---|
| F12 | **Wintun 适配器须有打开会话（connected）路由才进 `route print -4` active 视图**：无会话时适配器 disconnected——`route add` 与 `route delete` 均 exit 0（表确实在改，恢复面 delete 也成功），但 `route print` 不见该路由；开会话后立见。RIL-033 同口径（先会话后路由） | 首跑（无会话）：P3 `route_up=false` 而服务日志 `SVC APPLY-ROUTE OK` + 重启 `SVC RECOVER undone=1`（delete 成功=路由在表）；P5 `up_before=false reasserted=false` 同因。修后（P2 `start_session(0x40000)` 持至 P7）：全部 `route_up=true / up_before=true / reasserted=true` |
| F13 | **服务 `RUNNING` 状态先于 body 置位**（SCM 常规：快报 RUNNING 再干活）——编排侧检查路由须轮询而非瞬时断言，否则抢跑 body 的 `route add` | 首跑 P3 抢跑假阴性，改为 `poll_until(15, route_present)` 后 `route_up=true` |
| F14 | **SCM 崩溃自动重启走 ImagePath 不带 `StartServiceW` 参数**——服务据此区分两态（带参=装路由，无参=纯恢复），这正是「服务崩溃→重启→无参恢复」闭环的机制面 | 服务日志两段 `SVC START args=[...]` / `args=[]`；重启段 `SVC RECOVER undone=1` |
| F15 | **服务崩溃（`taskkill /F`）→ SCM 失败动作（SC_ACTION_RESTART, 5s）自动重启 + 状态翻新 pid**——`QueryServiceStatusEx` 的 dwProcessId 是定位面（服务进程即 probe.exe，按映像名会误杀编排者） | `svc_pid=82108 killed=true restarted=true`（restarted=状态 RUNNING 且 pid≠82108） |

## 3. 签名与依赖限制（公开记录）

- `probe.exe: NotSigned`（未签名——无代码签名证书；服务仍可载，本机未开签名强制策略）
- `wintun.dll: Valid`（WHQL 签名通过；驱动面由 wintun 自身签名保障，应用面未签名——诚实记录，不冒充）
- 依赖校验：`sc query wintun` → `TYPE: 1 KERNEL_DRIVER`（在册，STOPPED——按需装载）；`running_driver_version=0x0000000E`（0.14 风格编码）非 0 = 驱动已装载可运行

## 4. 边界与缺口（诚实注记）

- **休眠（suspend/resume）未真机实测**：验收「休眠」场景与「切网」收敛到同一恢复机制（账本 + `plan_for_event` 路由重放，P5 已证），差别只在触发面；但真机挂起会中断共享主机上同租户的会话与隧道，须独占窗口——如实记录为具名缺口，不伪装已解（同 RIL-034 P5 重构纪律）。
- **DNS 形状不重放**：`handle_network_event_windows` 对 netsh DNS 劫持形状跳过（切网时监听地址可能随接口变化——跟随归 DNS 服务面），此语义由 OS-free 单测覆盖（`win_recover_network_event_reassert_replays_routes_skips_dns_hijack` 断言执行器仅收 route 形状）；本批未在真机做 DNS 劫持（验收「不遗留 DNS」由「从不写 DNS + 账本仅路由条目」闭合——真机未触碰任何 DNS 配置）。
- **`user_id`/身份面**：本批未涉及（归 RIL-034 已证契约）；服务面全程 LocalSystem 上下文，编排者管理员会话。

## 5. 清理（幂等、不遗留）

- P7：`route delete 198.51.100.0 mask 255.255.255.0`（按目的+掩码，不依赖适配器在）→ `netsh interface ip delete address` → `EndSession`+`CloseAdapter`（适配器移除，RIL-033 实证）→ `CrashJournal.clear`。AFTER：服务 1060 未安装、适配器无、路由无、账本空、无残留 probe 进程。
- 全批未触任何真实网络/WireGuard 服务（隔离面 = 自建 `ril035-probe` Wintun 适配器 + 198.51.100.0/24 保留网段）。

## 6. 运行记录（净场单跑全文）

```
RIL035 RUN START 2026-11-21 16:03:27
HostName=IMAC IsAdmin=True
----- BEFORE service state (expect absent / 1060) -----
[SC] EnumQueryServicesStatus:OpenService 失败 1060:
指定的服务未安装。
----- BEFORE adapter (expect none) -----
----- BEFORE route (expect none) -----
----- BEFORE journal (expect empty) -----
(no journal file)
----- SIGNATURE (公开记录：签名与依赖限制) -----
probe.exe: NotSigned 未找到文件 ... (unsigned)
wintun.dll: Valid 签名已通过验证。
----- DRIVER DEPENDENCY (wintun service present) -----
SERVICE_NAME: wintun
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 1  STOPPED
----- PROBE OUTPUT (orchestrator, admin session) -----
PROBE P0-BASELINE OK service_absent=true route_absent=true adapter_absent=true
PROBE P1-SCM-INSTALL OK service_registered=true start_type=demand failure_action=restart(5s) image="C:\Users\cui\ril035\probe.exe"
PROBE P2-ADAPTER OK if_index_os=42 if_index_luid=0 addr_set=true session_up=true
PROBE P3-CRASH-RECOVER OK running=true route_up=true journaled=true svc_pid=82108 killed=true restarted=true recovered_route_absent=true log_recover=true
PROBE P4-STOP-UNINSTALL OK stopped=true deleted=true route_absent=true journal_empty=true
PROBE P5-NETCHANGE-REASSERT OK up_before=true gone_after_loss=true action=reassert_routes reasserted=true recover_undone=1 clean=true
PROBE P6-DRIVERS OK running_driver_version=0x0000000E (0.14 风格编码) sc_query_wintun=true signature=见 run.ps1 Get-AuthenticodeSignature
PROBE P7-CLEANUP OK adapter_absent=true route_absent=true service_absent=true journal_empty=true
PROBE OVERALL OK all sections passed (8 sections)
PROBE EXIT=0
----- AFTER service state (expect absent / 1060) -----
[SC] EnumQueryServicesStatus:OpenService 失败 1060:
指定的服务未安装。
----- AFTER adapter (expect none) -----
----- AFTER route (expect none) -----
----- AFTER journal (expect empty) -----
----- AFTER svc.log (service recovery evidence) -----
SVC START args=["apply-route", "198.51.100.0", "255.255.255.0", "198.51.100.1", "9999", "42"]
SVC RECOVER undone=0 already_gone=0 failed=0 snapshots_restored=0 snapshots_skipped=0
SVC APPLY-ROUTE OK
SVC BODY DONE idle-until-stop
SVC START args=[]
SVC RECOVER undone=1 already_gone=0 failed=0 snapshots_restored=0 snapshots_skipped=0
SVC BODY DONE idle-until-stop
----- AFTER probe processes (expect none after this session exits) -----
(current orchestrator pid = 84244; empty above = no leftover service/helper)
RIL035 RUN END 2026-11-21 16:03:39
```
