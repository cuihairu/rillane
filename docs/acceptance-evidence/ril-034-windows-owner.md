# RIL-034｜Windows 进程适配——真机证据

- **实机日期**：2026-11-21 13:54–14:35（+08:00；输出均实跑，时间戳见文末段）
- **证据机**：`imac`（ssh 直达，用户 `cui`，SSH 会话 High Mandatory Level——管理员等效；主机名 `IMAC`）
- **交付物**：`crates/rillane-platform/src/network/win_owner_ffi.rs`（真机 FFI：iphlpapi 表探针 + kernel32 身份源，`WinOwnerResolver::with_real_sources()` 装配口）、`examples/win_owner_probe.rs`（验收序列探针）
- **探针部署**：Linux 交叉编译 `x86_64-pc-windows-gnu`（release）→ scp `probe.exe` 到 imac `C:\Users\cui\ril034\`，`run.ps1` 编排（管理员会话实跑 + `runas /trustlevel:0x20000` 降权短序列）

## 1. 验收映射（todo RIL-034 验收原文 → 探针段）

| 验收项 | 探针段 | 实跑输出 |
|---|---|---|
| 同目标多进程 | P1 | 3 helper 连同一目标端口 → 各归各 pid，反向键全归父 pid，零串扰 |
| UDP | P2/P4 | helper 持 UDP 端口 → Known(helper pid) |
| 进程退出 | P2/P3 | kill → 表行消失（直探 Absent）→ NotFound（负缓存命中仍回验） |
| 端口复用 | P4/P4b | UDP 固定口 A→B 翻缓存；TCP SO_REUSEADDR 重绑 C→D 翻缓存 |
| 权限失败 | P5 | std 降权 token 下 OpenProcess err=5 → 身份拒绝实证 |
| unknown 策略 | P6 | 确无归属端口 → Absent / Unknown(NotFound)（策略应用归 RIL-015/016） |

```
PROBE P0-SELF-TCP OK pid=64556 started=1795242876633 path=Some("probe.exe")
PROBE P1-MULTIPROC OK pids=[65502->76344,65503->38704,65504->67168] reverse=own
PROBE P2-UDP OK pid=81368 started=1795242876692 path=Some("probe.exe"); after exit NotFound
PROBE P3-EXIT-NEGCACHE OK pid=69520 started=1795242876907 path=Some("probe.exe"); direct=Absent resolve=NotFound x2
PROBE P4-REUSE OK A pid=73696 -> B pid=76532 (cache flipped)
PROBE P4b-TCP-REBIND INFO tcp rebind (SO_REUSEADDR): C pid=72224 -> D pid=77068 flip ok
PROBE P5-INFO self path=Some("probe.exe"); identity(5696)=Some("MsMpEng.exe") readable under admin (host PPL off) — denial evidence = std run
PROBE P6-UNKNOWN OK tcp+udp unbound -> Absent / Unknown(NotFound)
PROBE OVERALL OK all sections passed
PROBE EXIT=0
```

降权段（runas /trustlevel:0x20000，同一 probe.exe `std` 模式，run.ps1 断言）：

```
STD-UDP-SELF pid=42528 own=true
STD-TCP-SELF pid=42528 own=true
STD-IDENTITY-SELF ok started=1795242877846 path=Some("probe.exe")
win_owner_ffi: OpenProcess(5696) failed err=5
STD-PPL denied=true
PROBE P5-PERMDENIED OK self=ok ppl(5696)=denied (OpenProcess err=5, see stderr)
STD-P5-PERMDENIED OK
```

## 2. 真机事实（F7–F11）

| # | 事实 | 实证 |
|---|---|---|
| F7 | **本机无 PPL 执行面：admin token + `PROCESS_QUERY_LIMITED_INFORMATION` 读 MsMpEng（5696）与 csrss（1468）身份均不被拒**——admin 级身份拒绝在本机不是自然可达用例，P5 门禁改由 std 降权 token 承担（设计演进：首版 P5 要求 admin 身份拒读 → FAIL 真事实 → 按事实重构为「提权信息面 + std 门禁」，不伪造拒绝） | 首跑 `P5-PERMDENIED FAIL identity(PPL 5696)=Some(Some("MsMpEng.exe"))`；试探 `identity(1468)=Some(Some("csrss.exe"))`；末跑 `PROBE P5-INFO … readable under admin (host PPL off)` |
| F8 | **标准用户 token 下 `OpenProcess(MsMpEng)` 被拒（`err=5` ERROR_ACCESS_DENIED）→ 身份源返回 None**——这就是本机真实的权限失败面：契约口径（身份查无一律 NotFound，win_owner 模块头）在真机闭合 | std 段两行 `win_owner_ffi: OpenProcess(5696) failed err=5` + `STD-PPL denied=true` + 门禁 `PROBE P5-PERMDENIED OK` |
| F9 | **标准用户可读 GetExtendedTcpTable owner 表**（OWNER 表不需提权）——表探针级 `Denied`（GetExtendedUdpTable ERROR_ACCESS_DENIED）在本机两个 token 下均不可达；该契约路径由 OS-free 注入面覆盖，如实记录不冒充 | std 段 `STD-UDP-SELF pid=42528 own=true` / `STD-TCP-SELF pid=42528 own=true`（降权 token 仍查到归属） |
| F10 | **表行字节序解码一次命中**：地址=网络序 DWORD（`Ipv4Addr::from(u32::from_be(raw))`）、端口=低 16 位网络序（`u16::from_be`）——按已知端口查到自己的行即为证（错码则 P0/P1 查无即 FAIL，未发生） | P0/P1/P2 全段匹配成功、pid 对照全部一致 |
| F11 | **TCP TIME_WAIT + SO_REUSEADDR 重绑：两行并存（残留 OwningPid=0 + 新连接活行）**，探针优先非零 pid 的分支被真机触发且正确 | `P4b-TCP-REBIND INFO … C pid=72224 -> D pid=77068 flip ok` |

## 3. 清理（幂等、不遗留）

- 探针自身：所有 helper 进程经 KillOnDrop（Err 路径也 kill+wait）；末跑 AFTER `probe` 进程 0、固定口 53187/53189/53191/53192 全无监听（`netstat` 空）。
- 本批次机上卫生：RIL-033 的两个 `ril033\probe.exe` 僵留进程（11:24:07/11:29:17 启动，OVERALL 输出后未退出）按 PID 清除（`taskkill /PID 74032 /F`、`77008 /F`）；RIL-034 探针两跑均退出干净（BEFORE/AFTER 计数 0）。
- 全程未触任何 `wg*`/系统配置（纯读表 + 临时 helper 进程）。

## 4. 边界与缺口（诚实注记）

- **`user_id` 恒 None**：Windows token SID/RID 口径归后续批次，不拿 Linux uid 语义冒充（win_owner_ffi 模块头已注明）。
- **同 pid 同端口 TTL 窗口复用残留**：win_owner 模块头具名缺口（表无启动时间列），本批未观测到（TTL 500ms 短界 + OS-free 测覆盖机制），按短 TTL 取舍不伪装已解。
- **P5 门禁所在 token**：降权 `runas /trustlevel:0x20000` 子进程（run.ps1 断言 `PROBE P5-PERMDENIED OK` 行）；PPL 候选由 run.ps1 以 `MsMpEng` pid 注入 `RIL034_PPL_PID`。本机 PPL 未启用（F7）——若未来启用了 PPL 面，admin 级拒绝亦会自然出现，本批证据链不受影响。
- **std 跑的 stderr 诊断**（`OpenProcess err=5`）经 cmd 重定向保留在 std_out.txt，为 F8 原始凭据。
