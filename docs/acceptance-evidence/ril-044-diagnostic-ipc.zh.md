# RIL-044 移动宿主有界诊断 IPC（本地可核验段，2026-11-27）

## 交付内容

`crates/rillane-ffi/tests/diagnostic_ipc_contract.rs`（2/2 绿）以**真实 Unix
域套接字往返**对已启动的 FFI runtime 钉住 RIL-044 生命周期条款的最后一
段：授权宿主诊断 IPC。边界依据 `docs/design/debug-and-mcp.md`——移动 VPN
扩展不默认跑 MCP、不新增手机入站管理端口；授权宿主 IPC 或脱敏导出是正路。
本桥仅显式启动：

- **无默认监听**：宿主未调 `rillane_ffi_diagnostic_ipc_start(handle, path)`
  前，连接宿主自选 UDS 路径必失败；没有默认路径，也没有默认监听 socket。
  二次启动（即使换路径）以 `ipc.start.duplicate_path` 拒绝——一进程一桥，
  不静默换绑。
- **只读动词**：行帧协议仅收六个动词——`stats`、`routing`、`nodes`、
  `dns_stats`、`dns_resolvers`、`flows`。`write`、`probe`、`config`、
  `apply`、`reload` 与未知动词一律回 `ipc.request.unknown_verb`，绝不旁路
  MCP 写入面。五个动词应答与对应 C 查询面逐字相等（共用同一 DTO 构造），
  `stats` 面九键齐全。
- **有界帧与资源**：一行一请求；无换行的请求超 8 KiB 回
  `ipc.request.oversize`，不无界缓冲；应答截到 256 KiB 的 UTF-8 合法边界；
  单请求 5 秒超时；accept 线程 100 ms 内可见 stop 旗标；每连接一请求一应答
  即收。
- **稳定错误码**：NULL 句柄 → `ipc.start.null_handle`；空路径 →
  `ipc.start.bad_path`；重复启动 → `ipc.start.duplicate_path`；未运行即停 →
  `ipc.stop.already_stopped`，均可从 `last_error` 读取。
- **停止顺序**：显式停止解绑路径并拒新连接；`rillane_ffi_stop(handle)` 亦
  在 runtime 关停前自动收桥，accept 线程不会活得比句柄持有的 `Arc<Runtime>`
  更久。
- **桥接面同步**：两个 C 导出声明于 `crates/rillane-ffi/include/rillane_ffi.h`、
  登记进 RIL-082 账本（`contracts/mobile_diagnostic_bridge_v1.json` 事务），
  并在 JNI 桥与 Kotlin `RillaneFfi` 镜像为 `diagnosticIpcStart` /
  `diagnosticIpcStop`（恰等门现钉 18 方法）。两个 C 查询面重构到 IPC 分派
  共用的 DTO 构造器，「同形状」是共享代码事实，不是拷贝。

## 如实边界

本段是宿主进程内核心半边。Android VpnService / iOS NE 的接线（触发显式
起桥的授权决策与路径选择）与真机行为（同意 UI、arm64、桥运行中的
Wi-Fi ↔ 蜂窝切换）归 RIL-043/RIL-046 真机批次，保持开放。不新增 MCP 服务、
JSON-RPC 端点或默认手机入站端口；UDS 路径由宿主显式提供，绝不默认。
父勾选保持关闭。
