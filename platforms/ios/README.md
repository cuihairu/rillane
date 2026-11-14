# RILLANE iOS（P3-4）

Rust 核心（`crates/rillane-ffi` cdylib）+ `NEPacketTunnelProvider` extension。
本目录提供：Provider Swift 源码、macOS 侧 xcframework 构建脚本、集成步骤。
**本仓开发环境为 Linux，iOS 面只能出源码与脚本，无法在本机完成 Xcode 构建与
真机/模拟器运行验证**（边界见下）。xcframework 现由 `librillane_ffi.dylib` 三面
组装，dylib 面 extension 链接/分发形态**未在本仓实证**；静态 `.a` 路径见
`build.sh::build_one` 备用函数，当前未接通。

## 内容

- `RillanePacketTunnelProvider.swift`——Provider 最小通路：`startTunnel` 起
  完整 rillane runtime（配置经 App Group 首选项，缺省兜底与 Android
  assets 同形）→ `setTunnelNetworkSettings`（`10.111.0.2/24`，仅接管
  `10.111.0.0/24` 测试网段，口径同 Android demo）→ packetFlow fd 交
  `rillane_ffi_tun_start`（ICMP echo 轮转，`ping 10.111.0.1` 验一轮流量）；
  `stopTunnel` 走 `rillane_ffi_stop`。
- `build.sh`——**macOS** 侧：`aarch64-apple-ios` / `aarch64-apple-ios-sim` /
  `x86_64-apple-ios` 三面 `cargo build` → `xcodebuild -create-xcframework`
  （头文件引 `crates/rillane-ffi/include/rillane_ffi.h`）。

## 集成步骤（macOS + Xcode）

1. `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
   后跑 `platforms/ios/build.sh`，产物 `platforms/ios/build/rillane_ffi.xcframework`；
2. 新建 iOS App 工程 + Packet Tunnel Provider extension target，把
   xcframework 拖入 extension 的 Link Binary With Libraries（dylib 面链接形态
   未实证，见头注）；
3. extension 的 bridging header 引入 `rillane_ffi.h`（或 Swift Package
   module map）；把 `RillanePacketTunnelProvider.swift` 放入 extension target；
4. extension `Info.plist` 声明 `NSExtensionPointIdentifier =
   com.apple.networkextension.packet-tunnel`；App Group
   （`group.dev.rillane.shared`）勾选 App 与 extension 两 target；
5. 宿主 App 用 `NETunnelProviderManager` 建 VPN Profile 并下发配置，同时
   **把配置 YAML 写进 App Group `UserDefaults(suiteName: "group.dev.rillane.shared")`
   的 `rillaneConfigYaml` 键**——Provider 的 `loadConfigYaml()` 从该处读取
   （`saveProviderConfiguration` 的 providerConfiguration 字典不被读取，
   只写它会恒走 Provider 内置 default 配置）；
6. 起 VPN 后在设备上 `ping 10.111.0.1` 验一轮流量。

## 验证边界（如实说明）

- **已验**：C ABI 本体（宿主 Rust 测试，见 `crates/rillane-ffi`）；Swift 源码
  仅语法级自查，**未过 Xcode 编译**（无 macOS 工具链）；fd 交接
  （KVC `socket.fileDescriptor`）与 NE 生命周期未在真机运行。
- TCP/UDP 真实代理路径随 P1-2 TunIngress 接入；当前 TUN 面仅 ICMP echo
  轮转，全局路由在此之前不开启。
- Network Extension 需付费开发者账号的 entitlement，本地模拟器可跑
  `aarch64-apple-ios-sim` 面但 NE extension 不支持模拟器运行——真机为
  唯一验收环境。
