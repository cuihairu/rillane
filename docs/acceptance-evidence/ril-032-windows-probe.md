# RIL-032｜Windows 技术探针——实测证据

- **巡检日期**：2026-11-15 20:51–21:06（+08:00，各段输出内含 `Get-Date -Format o` 实时戳）
- **证据机（主）**：`imac`（ssh 直达，主机名 `imac`，用户 `imac\cui`）
  - OS：Microsoft Windows build **10.0.26300.9974**（Windows 11）
  - 权限：SSH 会话完整性级别 **High Mandatory Level（S-1-16-12288）**——管理员等效（`whoami /groups` 实测）
  - wireguard-tools：**v1.0.20260223**（`wg --version` 实测；安装目录仅 `wg.exe` + `wireguard.exe`，**无 wg-quick**——隧道走 `wireguard.exe /installtunnelservice` 官方 headless 路径）
- **备机**：`openclaw`（10.147.19.49）巡检时段离线（`ssh: No route to host`，2026-11-15 两次复测）——本批证据全部来自 imac 主机，备机后续补测不改变结论。
- **探针程序**：单文件 Rust（std + socket2），在 Linux 交叉编译 `x86_64-pc-windows-gnu`（mingw-w64），scp 到 imac 实跑（imac 本地 scoop cargo shim 在非交互 SSH 下失效，实测 `Shim: Could not create process`——交叉编译为替代路径，证据全部来自 imac 上的真实执行）。源码全文见附录。

## 1. 驱动清单与最低版本（pnputil 实测）

```
发布名称:     oem14.inf
> 原始名称:      wintun.inf
> 提供程序名称:      WireGuard LLC
  类 GUID:         {4d36e972-e325-11ce-bfc1-08002be10318}（Net）
  驱动程序版本:     10/13/2021 0.14.0.0
  签名:             Microsoft Windows Hardware Compatibility Publisher（WHQL）

发布名称:     oem68.inf
> 原始名称:      wireguard.inf
> 提供程序名称:      WireGuard LLC
  类 GUID:         {4d36e972-e325-11ce-bfc1-08002be10318}（Net）
  驱动程序版本:     05/06/2026 1.1.0.0
  签名:             Microsoft Windows Hardware Compatibility Publisher（WHQL）
```

**选型记录**：wireguard-tools 1.0.20260223 的隧道服务创建的适配器 `InterfaceDescription = "WireGuard Tunnel"`，使用 **wireguard-nt（wireguard.inf 1.1.0.0）**——Wintun（wintun.inf 0.14.0.0）在机上共存但本批适配器实测走 wireguard-nt 后继驱动。两者均 WHQL 签名、均可直接使用；rillane Windows 侧实现应按 wireguard-nt 为主、Wintun 兼容为目标（同一 Net 类 GUID、同 Admin 权限要求）。

**最低权限**：隧道安装/卸载（`/installtunnelservice`、`/uninstalltunnelservice`）与适配器/路由操作在 High integrity 会话实测成功；标准用户不可预期成功（wireguard-nt 服务安装要求 Administrators）——与 WireGuard 官方要求一致。

## 2. TCP 本机归因（Get-NetTCPConnection / Get-Process / Win32_Process）

探针在 imac 发起 `probe.exe tcp 192.168.5.188:19532`（Linux 对端 `nc -l` 监听），保持期间 PowerShell 抓取（`CAPTURE-TIME: 2026-11-15T20:56:35.4222540+08:00`，HOST: IMAC）：

```
TCP-ROW: local=192.168.5.117:55223 remote=192.168.5.188:19532 state=Established pid=40288
PROC-PATH: C:\Users\cui\ril032\probe.exe
PROC-START: 2026-11-15T20:56:31.2248689+08:00
WMI-CREATED: 11/15/2026 20:56:31 exe=C:\Users\cui\ril032\probe.exe
```

探针自身输出（同一次连接）：

```
PID=40288 TARGET=192.168.5.188:19532 LOCAL=0.0.0.0:55223
RESULT=connected
```

Linux 对端接收确认连接成立。**字段结论**：TCP 四元组行含 OwningProcess ✅；`Get-Process -Id` 给出**完整可执行路径** ✅；`StartTime`/`Win32_Process.CreationDate` 一致给出**进程创建时刻**（owner.rs 契约的 `started_at_unix_ms`，PID 复用防护字段）✅。

## 3. UDP 本机归因（Get-NetUDPEndpoint）

探针 `probe.exe udp 192.168.5.188:19533 "ril032-udp-v3"` 发送数据报（Linux 对端 `nc -u -l` **实收 `ril032-udp-v3`**），保持期间抓取：

```
UDP-PROBE-PID: 46348
UDP-ROW: local=0.0.0.0:61050 pid=46348
UDP-PROC-PATH: C:\Users\cui\ril032\probe.exe
```

**字段结论**：UDP endpoint 行含 OwningProcess（PID 归因）✅，进程完整路径可查 ✅。**不可用字段（如实记录，todo 原文允许）**：
- 未显式 bind 的 UDP socket 行显示**通配 `0.0.0.0`** 本地地址——接口级归属须由 rillane 显式 bind 到接口地址后才有（探针已验证 bind 路径可用，见 §4）；
- `Get-NetUDPEndpoint`/本批 PowerShell 面不提供 UDP owner **module 路径**（TCP 侧 `GetOwnerModuleFromTcpEntry` 的等价物在 UDP 上不可用）——rillane Windows UDP 归因按 PID+创建时刻+完整路径建模，不声称 owner module 字段。

## 4. 原型防环（同一目标双连接对比：不绑定 vs 绑定物理口 IP）

**实验面**：`wireguard.exe /installtunnelservice` 建临时隧道 `wgprobe`（AllowedIPs=**198.18.0.0/15** 基准保留段、Endpoint=127.0.0.1:1 永不握手、Address=172.16.77.2/32）——不触碰默认路由，不影响真实流量：

```
--- ADAPTER ---
Name                 : wgprobe
InterfaceDescription : WireGuard Tunnel
ifIndex              : 65
Status               : Up
--- ROUTE 198.18.0.0/15 ---
DestinationPrefix : 198.18.0.0/15
InterfaceAlias    : wgprobe
InterfaceIndex    : 65
RouteMetric       : 0
```

**OS 未绑定路由决策（Find-NetRoute 实测——捕获成立）**：

```
--- FIND-NETROUTE unbound decision for 198.18.0.1 ---
IPAddress      : 172.16.77.2
InterfaceAlias : wgprobe
InterfaceIndex : 65
```

**未绑定 socket 被捕获进隧道（TCP 表轮询，2026-11-15T21:05:25 起，2s 间隔）**：

```
SAMPLE1: local=172.16.77.2:54435 remote=198.18.0.1:9 state=SynSent pid=17024
SAMPLE2..7: 同行持续（SynSent 直至 wg 永不握手超时）
RESULT=failed err=由于连接方在一段时间后没有正确答复... (os error 10060)
```

`wg show` 传输计数同步增长（`0 B received, 13.01 KiB sent`——SYN 流量确实进入隧道队列）。

**绑定物理口 IP——防环原语成立（同目标 198.18.0.1:9）**：

```
BIND=192.168.5.117
PID=11492 TARGET=198.18.0.1:9 LOCAL=192.168.5.117:54097
RESOLVED-LOCAL=192.168.5.117:54097
FINAL-LOCAL=192.168.5.117:54097
RESULT=failed err=... (os error 10060)   # 目标经物理口同样不可达——预期
```

**结论**：Windows 上 rillane 的防环原语为「出站 socket 显式 bind 到物理接口地址」——绑定后同一捕获网段目标全程钉在物理口（192.168.5.117），不再被隧道路由吸走（对照未绑定行的 `local=172.16.77.2` 捕获态）。此即 RIL-033 Windows 接管实现的 socket 级防环机制原型证据。

**备注（Windows 与 Linux 的 getsockname 语义差异，实现时须知）**：非阻塞 connect 发起后、完成前，`getsockname` 返回 `0.0.0.0:<port>`（Linux 则立刻返回已选源）——rillane 侧不能以 connect 早期 getsockname 判定源接口，须以绑定值或 TCP 表行为准；探针输出中 `RESULT=connected` 表示「hold 结束时 SO_ERROR 为空（仍在进行）」而非三次握手完成，以 TCP 表行状态为准。

**清理验证**：`/uninstalltunnelservice wgprobe` 后实测——服务无 `WireGuardTunnel$wgprobe`、适配器 `wgprobe` 不存在、路由 `198.18.0.0/15` 不存在（错误信息即 Not Found，幂等可重入）。

## 5. owner.rs 契约字段覆盖核对

| owner.rs 字段 | Windows 实测来源 | 结论 |
|---|---|---|
| `pid` | `Get-NetTCPConnection.OwningProcess` / `Get-NetUDPEndpoint.OwningProcess` | ✅ TCP+UDP 都可得 |
| `started_at_unix_ms` | `Get-Process.StartTime` == `Win32_Process.CreationDate` | ✅ PID 复用防护可行 |
| `executable_path` | `Get-Process.Path` / `Win32_Process.ExecutablePath` | ✅ 完整路径（非短名冒充） |
| `process_name` | `Get-Process` Name | ✅（无 Linux comm 15 字符截断问题） |
| UDP owner module 路径 | （无公开面） | ❌ **不可用字段**——按 §3 记录 |

## 附录：探针源码（单文件，std + socket2）

```rust
// RIL-032 Windows 技术探针：本机归因 + 原型防环原语证据。
// 用法：
//   probe whoami
//   probe tcp <ip:port> <hold_ms>                    # 不绑定——路由决定源接口
//   probe tcpbind <ip:port> <bind_ip> <hold_ms>      # 绑定物理口 IP——防环原语
//   probe udp <ip:port> [bind_ip] <msg> <hold_ms>    # 单数据报 + 保持端口可归因
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    match mode {
        "whoami" => {
            println!("PID={}", std::process::id());
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unavailable".into());
            println!("EXE={exe}");
        }
        "tcp" | "tcpbind" => {
            let target: SocketAddr = args[2].parse().expect("target ip:port");
            let hold_ms: u64 = args[args.len() - 1].parse().expect("hold_ms");
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .expect("tcp socket");
            if mode == "tcpbind" {
                let bind_ip: IpAddr = args[3].parse().expect("bind ip");
                socket
                    .bind(&SocketAddr::new(bind_ip, 0).into())
                    .expect("bind to interface ip");
                println!("BIND={bind_ip}");
            }
            socket.set_nonblocking(true).expect("nonblocking");
            let _ = socket.connect(&target.into());
            let local = socket
                .local_addr()
                .ok()
                .and_then(|a| a.as_socket())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unavailable".into());
            println!("PID={} TARGET={target} LOCAL={local}", std::process::id());
            // 源地址选择在 connect 发起后由系统解析——3s 后补读
            std::thread::sleep(Duration::from_secs(3));
            let resolved = socket
                .local_addr()
                .ok()
                .and_then(|a| a.as_socket())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unavailable".into());
            println!("RESOLVED-LOCAL={resolved}");
            std::thread::sleep(Duration::from_millis(hold_ms.saturating_sub(3_000)));
            let final_local = socket
                .local_addr()
                .ok()
                .and_then(|a| a.as_socket())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unavailable".into());
            println!("FINAL-LOCAL={final_local}");
            match socket.take_error() {
                Ok(None) => println!("RESULT=connected"),
                Ok(Some(e)) => println!("RESULT=failed err={e}"),
                Err(e) => println!("RESULT=take-error err={e}"),
            }
        }
        "udp" => {
            let target: SocketAddr = args[2].parse().expect("target ip:port");
            let bind_ip: Option<IpAddr> = args.get(3).and_then(|s| s.parse().ok());
            let (msg, hold_ms) = if bind_ip.is_some() {
                (args[4].clone(), args[5].parse().expect("hold_ms"))
            } else {
                (args[3].clone(), args[4].parse().expect("hold_ms"))
            };
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .expect("udp socket");
            if let Some(ip) = bind_ip {
                socket
                    .bind(&SocketAddr::new(ip, 0).into())
                    .expect("bind to interface ip");
                println!("BIND={ip}");
            }
            let n = socket.send_to(msg.as_bytes(), &target.into()).expect("send_to");
            let local = socket
                .local_addr()
                .ok()
                .and_then(|a| a.as_socket())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unavailable".into());
            println!(
                "PID={} TARGET={target} LOCAL={local} SENT={n} BYTES={}",
                std::process::id(),
                msg.len()
            );
            std::thread::sleep(Duration::from_millis(hold_ms));
            println!("RESULT=done");
        }
        _ => {
            println!("usage: probe whoami | tcp <ip:port> <hold_ms> | tcpbind <ip:port> <bind_ip> <hold_ms> | udp <ip:port> [bind_ip] <msg> <hold_ms>");
        }
    }
}
```
