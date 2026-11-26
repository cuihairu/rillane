# RIL-082 移动/路由器诊断桥接——本地账本

**类型**：本地可核验账本（非真机证据）。RIL-082 主勾选保持开放：真机 consent、arm64/iOS NE 生命周期、OpenWrt opkg/procd/kmod-tun 与签名验收仍未决。

机器可读真源为 `contracts/mobile_diagnostic_bridge_v1.json`，由 `crates/rillane-platform/tests/mobile_diagnostic_bridge_contract.rs` 在 `cargo test --workspace` 内钉死（九条测试，含三条 `#[should_panic]` 对账器自证）。

## 已钉住的面

- **无默认 MCP 服务、无手机入站管理端口**：FFI 导出恰为账本声明的 15 个 C ABI 符号（头文件 ↔ Rust 导出 ↔ 账本，精确集合）；`crates/rillane-ffi` 无 MCP 依赖，FFI/manifest/Kotlin/iOS/OpenWrt 源码不含 MCP/JSON-RPC/监听 socket 标记。Android `VpnService` 非 `exported`，受 `android.permission.BIND_VPN_SERVICE` 守卫；仅 launcher activity 导出。移动配置控制面落 `127.0.0.1:9090`。
- **授权宿主 IPC/脱敏导出**：移动宿主进程内直读 FFI 查询函数（flows/flow/stats/nodes/DNS/routing），无入站监听或模型协议端点。桌面侧集成消费**导出视图**，不是手机 MCP 服务。`rillanectl diagnose` 保持 `safe`（默认）、`full`、`raw` 三档、秘密键表与脱敏助手；`raw`（`--scope raw` / `--no-redact`）仅本地留存不脱敏文件，并显式标注 `do-not-upload`/`review-before-sharing` 与「永不自动上传诊断包」政策。
- **OpenWrt 可选资源受限适配器**：`platforms/openwrt/build.sh` 接受 `RILLANE_SMALL=1`，以 `--no-default-features --features small`（无 WASM/JIT）构建 `rillaned`+`rillanectl`。缺省档契约不变。ipk 不打包 `rillane-mcp`；模板控制面保持 loopback。本机 `cargo check -p rillaned -p rillanectl --no-default-features --features small` 与 `cargo test -p rillane-ffi --no-default-features --features mobile` 通过。
- **桌面桥接说明**：`docs/design/debug-and-mcp.md` 及其中文对照明确 Android/iOS 不在 VPN 服务/扩展内默认运行 MCP、不新增手机入站管理端口、先走授权宿主 IPC/脱敏导出，必要时由桌面适配器接入。

## 具名缺口（本批未验）

- 真机 Android consent/性能（arm64）与付费开发者账号 iOS Network Extension entitlement/生命周期；iOS Swift 仅语法自查（Linux 开发主机，无 Xcode）。
- OpenWrt opkg 安装/升级、procd respawn、kmod-tun 吞吐、nftables 透明接管真机行为。
- 本批仅跑了宿主目标特性 check，未做跨编译 small/mobile 二进制产物验证。
- 共享数据面 TCP/UDP 代理路径尚未移入移动 TUN demo（当前仅 ICMP echo 轮转，全局路由保持关闭）。

契约门钉住的是结构事实，不是设备行为：测试通过只表示源码与账本一致，不表示某台手机或路由器接受了流量。
